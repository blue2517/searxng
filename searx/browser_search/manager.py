# SPDX-License-Identifier: AGPL-3.0-or-later
"""Single Chromium runtime used by the browser-backed SearXNG engines."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import secrets
import shutil
import threading
import time
from typing import Any
from urllib.parse import urlencode, urlparse

from .auth_state import (
    extract_google_storage_state,
    get_google_auth_status,
    has_google_auth_cookies,
    is_google_cookie_domain,
    load_google_auth_state,
    merge_storage_states,
    resolve_google_auth_path,
    save_google_auth_state,
    update_google_auth_meta,
)
from .proxy_pool import ProxyEndpoint, ProxyPool
from .socks_bridge import Socks5AuthBridge

logger = logging.getLogger(__name__)


def _elapsed_ms(started_at: float) -> float:
    return round((time.perf_counter() - started_at) * 1000, 3)


def _timing_event(request: "SearchRequest", stage: str, **details: Any) -> None:
    payload = {
        "stage": stage,
        "engine": request.engine,
        "query": request.query,
        **details,
    }
    logger.warning(
        "browser-search-timing %s",
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    )


DEFAULT_DESKTOP_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)

BROWSER_ARGS = (
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-infobars",
    "--window-size=1280,800",
)

# Keep the page-level browser identity consistent with a normal Chrome session.
# The worker already disables the most visible automation flag at launch; these
# properties cover the corresponding DOM checks used by Google challenge pages.
BROWSER_STEALTH_SCRIPT = r"""
// WebGL Spoofing (removes SwiftShader / virtual GPU fingerprint)
const mockWebGL = (proto) => {
  if (!proto) return;
  const originalGetParameter = proto.getParameter;
  proto.getParameter = function(param) {
    if (param === 37445) { // UNMASKED_VENDOR_WEBGL
      return 'Intel Inc.';
    }
    if (param === 37446) { // UNMASKED_RENDERER_WEBGL
      return 'Intel(R) Iris(R) Xe Graphics';
    }
    if (param === 7936) { // VENDOR
      return 'WebKit';
    }
    if (param === 7937) { // RENDERER
      return 'WebKit WebGL';
    }
    return originalGetParameter.apply(this, [param]);
  };
  const originalGetExtension = proto.getExtension;
  proto.getExtension = function(name) {
    const ext = originalGetExtension.apply(this, [name]);
    if (name === 'WEBGL_debug_renderer_info' && ext) {
      return {
        UNMASKED_VENDOR_WEBGL: 37445,
        UNMASKED_RENDERER_WEBGL: 37446,
      };
    }
    return ext;
  };
};
mockWebGL(WebGLRenderingContext.prototype);
if (typeof WebGL2RenderingContext !== 'undefined') {
  mockWebGL(WebGL2RenderingContext.prototype);
}

// Remove webdriver flags and ensure clean Navigator prototype
if (Navigator.prototype.hasOwnProperty('webdriver')) {
  delete Navigator.prototype.webdriver;
}
Object.defineProperty(navigator, 'webdriver', { get: () => undefined, configurable: true });

Object.defineProperty(navigator, 'plugins', {
  get: () => [
    { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
  ],
  configurable: true,
});
Object.defineProperty(navigator, 'languages', {
  get: () => ['zh-CN', 'zh', 'en-US', 'en'],
  configurable: true,
});
if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) {
  window.chrome.runtime = {
    connect: () => {},
    sendMessage: () => {},
    onMessage: { addListener: () => {}, removeListener: () => {}, hasListener: () => false },
  };
}
delete window.__playwright;
delete window.__pw_manual;
if (navigator.permissions && navigator.permissions.query) {
  const query = navigator.permissions.query.bind(navigator.permissions);
  navigator.permissions.query = (params) => {
    if (params && (params.name === 'notifications' || params.name === 'clipboard-read')) {
      return Promise.resolve({ state: 'default', onchange: null });
    }
    return query(params);
  };
}
"""


@dataclass(frozen=True, slots=True)
class SearchRequest:
    query: str
    pageno: int = 1
    locale: str = "en-US"
    safesearch: int = 0
    time_range: str | None = None
    engine: str = "google"


@dataclass(frozen=True, slots=True)
class Route:
    name: str
    profile_key: str
    proxy: ProxyEndpoint | None = None


class BrowserSearchManager:
    """Own one Chromium instance and asynchronously multiplex search pages."""

    SUPPORTED_ENGINES = frozenset({"google", "duckduckgo"})

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.profile_root = Path(
            config.get("profile_dir", "/var/lib/searxng/browser-profiles")
        )
        self.google_auth_state_path = resolve_google_auth_path(config)
        self.persist_google_auth = bool(config.get("persist_google_auth", True))
        self.headless = bool(config.get("headless", True))
        self.browser_channel = (
            str(config.get("browser_channel", "chrome")).strip() or None
        )
        self.executable_path = str(config.get("executable_path", "")).strip() or None
        self.navigation_timeout = int(
            float(config.get("navigation_timeout", 30)) * 1000
        )
        self.selector_timeout = int(float(config.get("selector_timeout", 3)) * 1000)
        self.reuse_context_locale = bool(config.get("reuse_context_locale", True))
        try:
            consent_timeout = float(config.get("consent_timeout", 800))
        except (TypeError, ValueError):
            consent_timeout = 800.0
        self.consent_timeout = max(100, min(2000, int(consent_timeout)))
        # Route attempts and recovery attempts are separate.  The legacy
        # max_attempts setting remains accepted as the route-attempt fallback.
        try:
            configured_routes = int(
                config.get("max_route_attempts", config.get("max_attempts", 3))
            )
        except (TypeError, ValueError):
            configured_routes = 3
        self.max_route_attempts = max(1, min(8, configured_routes))
        self.max_attempts = self.max_route_attempts
        try:
            configured_recoveries = int(config.get("recovery_retries_per_route", 1))
        except (TypeError, ValueError):
            configured_recoveries = 1
        self.recovery_retries_per_route = max(0, min(1, configured_recoveries))
        try:
            configured_retry_delay = float(config.get("challenge_retry_delay", 2))
        except (TypeError, ValueError):
            configured_retry_delay = 2.0
        self.challenge_retry_delay = max(0.0, min(10.0, configured_retry_delay))
        try:
            configured_cooldown = float(config.get("route_cooldown_seconds", 10))
        except (TypeError, ValueError):
            configured_cooldown = 10.0
        self.route_cooldown_seconds = max(0.0, min(10.0, configured_cooldown))
        configured_user_agent = str(config.get("user_agent", "")).strip()
        self.user_agent = configured_user_agent or None
        self._resolved_user_agent = self.user_agent
        self._socks_bridges: dict[str, Socks5AuthBridge] = {}
        proxy_config = config.get("proxy_pool", {}) or {}
        if not proxy_config.get("entries"):
            try:
                from searx import get_setting

                outgoing_pp = get_setting("outgoing.proxy_pool", {}) or {}
                if outgoing_pp.get("entries"):
                    proxy_config = {
                        "enabled": bool(outgoing_pp.get("enabled", False)),
                        "entries": list(outgoing_pp.get("entries", [])),
                        "max_attempts": outgoing_pp.get("max_attempts", 3),
                    }
            except Exception:
                pass
        self.proxy_pool = ProxyPool(proxy_config.get("entries", []))
        self.proxy_pool_enabled = bool(proxy_config.get("enabled", False))

        self._playwright: Any = None
        self._browser: Any = None
        self._direct_context: Any = None
        self._contexts: dict[str, Any] = {}
        self._context_locales: dict[str, str] = {}
        self._context_active_pages: dict[str, int] = {}
        self._pending_context_close: set[str] = set()
        self._force_clean_context: set[str] = set()
        self._route_cooldowns: dict[str, float] = {}
        self._state_locks: dict[str, asyncio.Lock] = {}
        self._context_lock: asyncio.Lock | None = None
        self._start_lock: asyncio.Lock | None = None
        self._verify_lock: asyncio.Lock | None = None
        self._verify_session: dict[str, Any] | None = None
        self._verify_reaper_task: asyncio.Task[Any] | None = None
        self._last_challenges: dict[str, dict[str, Any]] = {}
        try:
            verify_ttl = float(config.get("verify_idle_ttl", 300))
        except (TypeError, ValueError):
            verify_ttl = 300.0
        self._verify_idle_ttl = max(60.0, min(3600.0, verify_ttl))

    @property
    def browser(self) -> Any:
        """Expose the singleton browser for diagnostics and focused tests."""

        return self._browser

    async def start(self) -> None:
        """Start exactly one Chromium instance and keep an identity host warm."""

        if self._start_lock is None:
            self._start_lock = asyncio.Lock()
        if self._context_lock is None:
            self._context_lock = asyncio.Lock()
        async with self._start_lock:
            if self._browser is not None:
                return
            try:
                from playwright.async_api import async_playwright
            except ImportError as exc:
                raise RuntimeError(
                    "browser search requires the optional Playwright dependency"
                ) from exc

            self.profile_root.mkdir(parents=True, exist_ok=True)
            playwright = await async_playwright().start()
            launch_kwargs: dict[str, Any] = {
                "headless": self.headless,
                "args": list(BROWSER_ARGS),
                "locale": self._normalize_locale(
                    str(self.config.get("prewarm_locale", "zh-CN"))
                ),
                "viewport": {"width": 1280, "height": 800},
            }
            if self.user_agent:
                launch_kwargs["user_agent"] = self.user_agent
            if self.executable_path:
                launch_kwargs["executable_path"] = self.executable_path
            elif self.browser_channel:
                launch_kwargs["channel"] = self.browser_channel

            direct_profile = self._direct_profile_path()
            try:
                try:
                    context = await playwright.chromium.launch_persistent_context(
                        str(direct_profile), **launch_kwargs
                    )
                except Exception:
                    if self.browser_channel and not self.executable_path:
                        launch_kwargs.pop("channel", None)
                        detected_exec = None
                        for candidate in (
                            "chromium",
                            "chromium-browser",
                            "google-chrome",
                            "chrome",
                        ):
                            found = shutil.which(candidate)
                            if found:
                                detected_exec = found
                                break
                        if detected_exec:
                            launch_kwargs["executable_path"] = detected_exec
                        context = await playwright.chromium.launch_persistent_context(
                            str(direct_profile), **launch_kwargs
                        )
                    else:
                        raise
                browser = context.browser
                if browser is None:
                    raise RuntimeError("persistent Chromium did not expose its Browser")
                self._playwright = playwright
                self._browser = browser
                # Keep the persistent context as a browser host/identity
                # holder.  Actual searches use disposable child contexts so a
                # challenged route can be replaced without restarting the one
                # Chromium instance.
                self._direct_context = context
                try:
                    await context.add_init_script(BROWSER_STEALTH_SCRIPT)
                except Exception:
                    logger.debug("failed to install browser stealth script", exc_info=True)

                # Persistent contexts can expose an initial about:blank tab.
                # It is not a search page and would otherwise inflate the
                # observed page count during concurrency diagnostics.
                blank_pages = [
                    page
                    for page in list(context.pages)
                    if str(page.url or "") in {"", "about:blank"}
                ]
                # Keep one host page alive.  Closing the last headed page makes
                # Chromium exit, which later turns a normal search into a
                # TargetClosedError.
                for initial_page in blank_pages[1:]:
                    try:
                        await initial_page.close()
                    except Exception:
                        logger.debug(
                            "failed to close initial blank page", exc_info=True
                        )
                if not blank_pages:
                    await context.new_page()

                if self.user_agent is None and self.headless:
                    probe = await context.new_page()
                    try:
                        native_user_agent = str(
                            await probe.evaluate("navigator.userAgent") or ""
                        ).strip()
                    finally:
                        await probe.close()
                    self._resolved_user_agent = (
                        native_user_agent.replace("HeadlessChrome/", "Chrome/") or None
                    )
                logger.info(
                    "browser-search-browser-started instance=%s contexts=%s",
                    id(browser),
                    len(browser.contexts),
                )
            except Exception:
                try:
                    await playwright.stop()
                finally:
                    self._playwright = None
                    self._browser = None
                    self._direct_context = None
                raise

    async def close(self) -> None:
        """Close all contexts and the singleton Chromium instance."""

        if self._verify_session is not None:
            try:
                await self._close_verify_session_locked()
            except Exception:
                logger.debug("failed to close verification session", exc_info=True)
        if self._browser is None and self._playwright is None:
            return
        contexts = list(self._contexts.items())
        self._contexts.clear()
        self._context_locales.clear()
        self._context_active_pages.clear()
        self._pending_context_close.clear()
        self._force_clean_context.clear()
        self._route_cooldowns.clear()
        for _, context in contexts:
            try:
                await context.close()
            except Exception:
                logger.debug("failed to close browser search context", exc_info=True)
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                logger.exception("failed to close browser")
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                logger.exception("failed to stop Playwright")
        self._browser = None
        self._direct_context = None
        self._playwright = None
        for bridge in list(self._socks_bridges.values()):
            bridge.close()
        self._socks_bridges.clear()

    @staticmethod
    def _normalize_locale(value: str | None, default: str = "") -> str:
        locale = str(value or "").strip().replace("_", "-")
        if not locale or locale.lower() in {"all", "auto"}:
            return default
        parts = locale.split("-")
        if not parts[0].isalpha() or len(parts[0]) not in {2, 3}:
            return default
        normalized = [parts[0].lower()]
        for part in parts[1:]:
            if not part.isalnum() or not 2 <= len(part) <= 8:
                return default
            if len(part) == 2 and part.isalpha():
                normalized.append(part.upper())
            elif len(part) == 4 and part.isalpha():
                normalized.append(part.title())
            else:
                normalized.append(part)
        return "-".join(normalized)

    def _context_key(
        self, route: Route, locale: str, engine: str = "google"
    ) -> str:
        key = f"{engine}-{route.profile_key}"
        if route.profile_key != "direct" and not self.reuse_context_locale:
            key = f"{key}-{self._normalize_locale(locale)}"
        return key

    def _direct_profile_path(self) -> Path:
        direct = self.profile_root / "direct"
        if direct.exists() and any(direct.iterdir()):
            return direct
        legacy_google = self.profile_root / "google-direct"
        if legacy_google.exists() and any(legacy_google.iterdir()):
            return legacy_google
        direct.mkdir(parents=True, exist_ok=True)
        return direct

    def _route_profile(self, route: Route) -> Path:
        path = self.profile_root / route.profile_key
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _state_path(self, key: str) -> Path:
        path = self.profile_root / key
        path.mkdir(parents=True, exist_ok=True)
        return path / "storage-state.json"

    def _proxy_config(self, proxy: ProxyEndpoint) -> dict[str, str]:
        if proxy.scheme == "socks5" and proxy.username:
            bridge = self._socks_bridges.get(proxy.key)
            if bridge is None:
                bridge = Socks5AuthBridge(proxy)
                bridge.start()
                self._socks_bridges[proxy.key] = bridge
            return bridge.playwright_config()
        return proxy.playwright_config()

    async def _create_context(self, route: Route, locale: str, key: str) -> Any:
        if self._browser is None:
            raise RuntimeError("browser search is not started")
        norm_locale = self._normalize_locale(locale, default="zh-CN") or "zh-CN"
        kwargs: dict[str, Any] = {
            "locale": norm_locale,
            "viewport": {"width": 1280, "height": 800},
            "user_agent": self.user_agent or DEFAULT_DESKTOP_UA,
        }
        if route.proxy:
            kwargs["proxy"] = self._proxy_config(route.proxy)
        state_path = self._state_path(key)
        force_clean = key in self._force_clean_context
        is_google = key.startswith("google")
        auth_state = (
            load_google_auth_state(self.google_auth_state_path) if is_google else None
        )
        route_state: dict[str, Any] | None = None
        if state_path.exists() and not force_clean:
            if auth_state is not None:
                try:
                    loaded = json.loads(state_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        route_state = loaded
                except Exception:
                    route_state = None
            else:
                kwargs["storage_state"] = str(state_path)
        elif (
            route.profile_key == "direct"
            and self._direct_context is not None
            and not force_clean
        ):
            # Migrate the existing persistent profile once.  This preserves a
            # known-good Cookie identity while the search Context remains
            # replaceable after a challenge.
            try:
                await self._direct_context.storage_state(path=str(state_path))
                if state_path.exists():
                    if auth_state is not None:
                        loaded = json.loads(state_path.read_text(encoding="utf-8"))
                        if isinstance(loaded, dict):
                            route_state = loaded
                    else:
                        kwargs["storage_state"] = str(state_path)
            except Exception:
                logger.debug("failed to seed direct storage state", exc_info=True)
        if auth_state is not None:
            kwargs["storage_state"] = merge_storage_states(route_state, auth_state)
        context = await self._browser.new_context(**kwargs)
        try:
            await context.add_init_script(BROWSER_STEALTH_SCRIPT)
        except Exception:
            logger.debug("failed to install browser stealth script", exc_info=True)
        if not state_path.exists() and not force_clean and auth_state is None:
            try:
                page = await context.new_page()
                seed_url = (
                    "https://duckduckgo.com"
                    if "duckduckgo" in key
                    else f"https://www.google.com/?hl={norm_locale}"
                )
                await page.goto(seed_url, wait_until="domcontentloaded", timeout=5000)
                await asyncio.sleep(0.8)
                await page.close()
                await self._save_state(key, context)
            except Exception:
                pass
        elif auth_state is not None and not state_path.exists():
            await self._save_state(key, context)
        if force_clean:
            self._force_clean_context.discard(key)
        self._context_locales[key] = norm_locale
        self._context_active_pages[key] = 0
        return context

    async def _context(
        self, route: Route, locale: str, engine: str = "google"
    ) -> tuple[str, Any]:
        await self.start()
        key = self._context_key(route, locale, engine)
        assert self._context_lock is not None
        async with self._context_lock:
            context = self._contexts.get(key)
            if context is None:
                context = await self._create_context(route, locale, key)
                self._contexts[key] = context
            return key, context

    async def _save_state(self, key: str, context: Any) -> None:
        if context is None:
            return
        lock = self._state_locks.setdefault(key, asyncio.Lock())
        async with lock:
            try:
                state_path = self._state_path(key)
                temp_path = state_path.with_suffix(".tmp")
                await context.storage_state(path=str(temp_path))
                temp_path.replace(state_path)
                logger.info("browser-search-state-saved context=%s", key)
            except Exception:
                logger.debug("failed to save browser state for %s", key, exc_info=True)

    async def _inspect_google_auth(
        self, page: Any, context: Any, results: list[dict[str, str]]
    ) -> tuple[bool | None, str]:
        has_login_link = False
        has_account_ui = False
        try:
            ui = await page.evaluate(
                """
                () => ({
                  hasLoginLink: Boolean(
                    document.querySelector('a[href*="accounts.google.com/ServiceLogin"]')
                  ),
                  hasAccountUi: Boolean(
                    document.querySelector(
                      'a[href*="SignOutOptions"], a[aria-label*="Google"], a[aria-label*="谷歌账号"], [data-ogsr-up]'
                    )
                  ),
                })
                """
            )
            if isinstance(ui, dict):
                has_login_link = bool(ui.get("hasLoginLink"))
                has_account_ui = bool(ui.get("hasAccountUi"))
        except Exception:
            pass

        has_auth_cookie = False
        try:
            cookies = await context.cookies(["https://www.google.com"])
            has_auth_cookie = has_google_auth_cookies(cookies)
        except Exception:
            pass

        all_goto = bool(results) and all(
            "google.com/goto" in str(item.get("url", "")) for item in results
        )
        if has_login_link and not has_account_ui:
            return False, "session_logged_out"
        if has_account_ui:
            return True, "authenticated"
        if has_auth_cookie:
            if results and not all_goto:
                return True, "authenticated_direct_urls"
            if all_goto:
                return False, "redirect_urls_only"
        return None, "unknown"

    async def _update_google_auth_after_search(
        self, page: Any, context: Any, results: list[dict[str, str]]
    ) -> None:
        if not self.google_auth_state_path.exists():
            return
        auth_ok, reason = await self._inspect_google_auth(page, context, results)
        if auth_ok is True:
            if self.persist_google_auth:
                try:
                    raw_state = await context.storage_state()
                    if isinstance(raw_state, dict):
                        google_state = extract_google_storage_state(raw_state)
                        if has_google_auth_cookies(google_state.get("cookies")):
                            save_google_auth_state(
                                self.google_auth_state_path,
                                google_state,
                                source_format="refresh",
                                last_auth_ok=True,
                                last_reason=reason,
                            )
                            return
                except Exception:
                    logger.debug(
                        "failed to refresh google auth state", exc_info=True
                    )
            update_google_auth_meta(
                self.google_auth_state_path, last_auth_ok=True, last_reason=reason
            )
        elif auth_ok is False:
            update_google_auth_meta(
                self.google_auth_state_path, last_auth_ok=False, last_reason=reason
            )
            logger.warning("google-auth-session-expired reason=%s", reason)

    async def _close_route(
        self,
        route: Route,
        clear_cookies: bool = False,
        engine: str = "google",
        locale: str = "en-US",
        reason: str = "route_reset",
    ) -> None:
        """Discard a route Context while preserving its last-good state."""

        key = self._context_key(route, locale, engine)
        context = self._contexts.get(key)
        if context is None:
            if clear_cookies:
                self._force_clean_context.add(key)
            return
        active = self._context_active_pages.get(key, 0)
        if active:
            if clear_cookies:
                self._force_clean_context.add(key)
            self._pending_context_close.add(key)
            return
        self._contexts.pop(key, None)
        self._context_locales.pop(key, None)
        self._context_active_pages.pop(key, None)
        if clear_cookies:
            self._force_clean_context.add(key)
        try:
            await context.close()
        except Exception:
            logger.debug("failed to close route context %s", key, exc_info=True)
        logger.info(
            "browser-search-context-discarded context=%s reason=%s clean_next=%s",
            key,
            reason,
            clear_cookies,
        )

    async def _release_page(self, key: str, context: Any, page: Any) -> None:
        try:
            await page.close()
        except Exception:
            pass
        active = max(0, self._context_active_pages.get(key, 1) - 1)
        self._context_active_pages[key] = active
        if active == 0 and key in self._pending_context_close:
            self._pending_context_close.discard(key)
            await self._close_context_key(key, context)

    async def _close_context_key(self, key: str, context: Any) -> None:
        current = self._contexts.pop(key, None)
        self._context_locales.pop(key, None)
        self._context_active_pages.pop(key, None)
        try:
            await (current or context).close()
        except Exception:
            logger.debug("failed to close pending route context %s", key, exc_info=True)

    async def _apply_page_profile(self, context: Any, page: Any, locale: str) -> None:
        if (
            not self.headless
            or self.user_agent is not None
            or not self._resolved_user_agent
        ):
            return
        try:
            accept_language = self._normalize_locale(locale)
            if not accept_language:
                accept_language = "zh-CN,zh;q=0.9,en;q=0.8"
            session = await context.new_cdp_session(page)
            await session.send(
                "Network.setUserAgentOverride",
                {
                    "userAgent": self._resolved_user_agent,
                    "acceptLanguage": accept_language,
                },
            )
        except Exception:
            logger.debug("failed to apply detected user agent", exc_info=True)

    @staticmethod
    def _google_url(request: SearchRequest) -> str:
        params: dict[str, str] = {
            "q": request.query,
            "gl": "hk",
        }
        locale = BrowserSearchManager._normalize_locale(request.locale)
        if locale:
            params["hl"] = locale
        if request.pageno > 1:
            params["start"] = str((request.pageno - 1) * 10)
        if request.safesearch:
            params["safe"] = "active"
        if request.time_range in {"day", "week", "month", "year"}:
            params["tbs"] = f"qdr:{request.time_range[0]}"
        return "https://www.google.com/search?" + urlencode(params)

    @staticmethod
    def _duckduckgo_url(request: SearchRequest) -> str:
        locale = BrowserSearchManager._normalize_locale(request.locale)
        params: dict[str, str] = {
            "q": request.query,
            "kl": locale.lower() if locale else "us-en",
            "kp": {0: "-2", 1: "-1", 2: "1"}.get(request.safesearch, "-2"),
        }
        if request.pageno > 1:
            params["s"] = str((request.pageno - 1) * 10)
        if request.time_range in {"day", "week", "month", "year"}:
            params["df"] = request.time_range[0]
        return "https://duckduckgo.com/?" + urlencode(params)

    @staticmethod
    def _is_transport_error(exc: Exception) -> bool:
        message = str(exc).lower()
        return any(
            marker in message
            for marker in (
                "err_connection_closed",
                "err_connection_reset",
                "err_proxy_connection_failed",
                "err_timed_out",
                "err_name_not_resolved",
            )
        )

    @staticmethod
    async def _page_snapshot(
        page: Any, selectors: tuple[str, ...]
    ) -> dict[str, Any] | None:
        try:
            snapshot = await page.evaluate(
                """
                (selectors) => ({
                  text: document.body ? (document.body.innerText || document.body.textContent || '') : '',
                  matches: selectors.map((selector) => {
                    try { return Boolean(document.querySelector(selector)); }
                    catch { return false; }
                  }),
                })
                """,
                list(selectors),
            )
            return snapshot if isinstance(snapshot, dict) else None
        except Exception:
            return None

    @classmethod
    async def _page_text(cls, page: Any) -> str:
        try:
            text = await page.evaluate(
                "() => document.body ? (document.body.innerText || document.body.textContent || '') : ''"
            )
            if isinstance(text, str):
                return text[:12000]
        except Exception:
            pass
        try:
            return str(await page.locator("body").inner_text(timeout=1000))[:12000]
        except Exception:
            return ""

    @classmethod
    async def _block_reason(cls, page: Any, engine: str = "google") -> str | None:
        url = str(getattr(page, "url", "")).lower()
        if engine == "duckduckgo":
            if any(marker in url for marker in ("/anomaly", "/challenge", "captcha")):
                return "duckduckgo_challenge_url"
            selectors = (
                "#anomaly-modal",
                "form#challenge-form",
                "iframe[src*='captcha']",
                "[data-testid='challenge']",
            )
            checks = (
                ("unfortunately, bots use duckduckgo too", "captcha"),
                ("please complete the following challenge", "captcha"),
                ("are you a robot", "captcha"),
                ("检测到异常流量", "unusual_traffic"),
                ("验证您不是机器人", "captcha"),
                ("enable javascript", "javascript_required"),
                ("update your browser", "browser_update_required"),
            )
        else:
            if any(marker in url for marker in ("/sorry/", "/challenge/", "captcha")):
                return "google_challenge_url"
            if "consent.google" in url:
                return "consent_required"
            selectors = (
                "form#captcha-form",
                "iframe[src*='recaptcha']",
                "iframe[src*='captcha']",
                "[id*='captcha']",
            )
            checks = (
                ("unusual traffic", "unusual_traffic"),
                ("our systems have detected unusual traffic", "unusual_traffic"),
                ("检测到异常流量", "unusual_traffic"),
                ("我们的系统检测到来自您的计算机网络的异常流量", "unusual_traffic"),
                ("enable javascript", "javascript_required"),
                ("update your browser", "browser_update_required"),
                ("i'm not a robot", "captcha"),
                ("recaptcha", "captcha"),
                ("请验证您不是机器人", "captcha"),
                ("确认您不是机器人", "captcha"),
                ("在继续使用 google 之前", "consent_required"),
                ("before you continue to google", "consent_required"),
            )
        snapshot = await cls._page_snapshot(page, selectors)
        text = str(
            snapshot.get("text", "") if snapshot else await cls._page_text(page)
        ).lower()
        for marker, reason in checks:
            if marker in text:
                return reason
        if snapshot and any(snapshot.get("matches", [])):
            return "captcha"
        return None

    async def _dismiss_consent(self, page: Any) -> bool:
        try:
            clicked = await page.evaluate(
                """
                () => {
                  const labels = ['accept all', 'i agree', '同意', '接受全部', '全部接受'];
                  const nodes = [...document.querySelectorAll('button, [role="button"], [aria-label]')];
                  const target = nodes.find((node) => {
                    const value = `${node.innerText || ''} ${node.getAttribute('aria-label') || ''}`.trim().toLowerCase();
                    return labels.some((label) => value.includes(label));
                  });
                  if (!target) return false;
                  target.click();
                  return true;
                }
                """
            )
            if isinstance(clicked, bool) and clicked:
                return True
        except Exception:
            pass
        try:
            locator = page.locator(
                'button:has-text("Accept all"), button:has-text("I agree"), '
                'button:has-text("同意"), button:has-text("接受全部"), '
                'button:has-text("全部接受"), [aria-label="Accept all"]'
            ).first
            if not await locator.is_visible(timeout=self.consent_timeout):
                return False
            await locator.click(timeout=min(1500, self.consent_timeout + 500))
            return True
        except Exception:
            return False

    @staticmethod
    async def _wait_for_results(page: Any, engine: str, timeout_ms: int) -> bool:
        deadline = time.perf_counter() + max(0, timeout_ms) / 1000
        while time.perf_counter() < deadline:
            try:
                matched = await page.evaluate(
                    """
                    (engine) => {
                      const selector = engine === 'duckduckgo'
                        ? 'article[data-testid="result"], [data-testid="mainline"] article, article'
                        : 'div#search h3, div#rso h3';
                      return Boolean(document.querySelector(selector));
                    }
                    """,
                    engine,
                )
                if isinstance(matched, bool) and matched:
                    return True
            except Exception:
                return False
            await asyncio.sleep(0.05)
        return False

    @staticmethod
    async def _extract_results(
        page: Any, limit: int = 10, engine: str = "google"
    ) -> list[dict[str, str]]:
        if engine == "duckduckgo":
            result = await page.evaluate(
                """
                (limit) => {
                  const text = (el) => (el?.innerText || el?.textContent || '').trim();
                  const out = [];
                  const seen = new Set();
                  const boxes = document.querySelectorAll(
                    'article[data-testid="result"], [data-testid="mainline"] article, article'
                  );
                  for (const box of boxes) {
                    if (out.length >= limit) break;
                    const anchor = box.querySelector(
                      'a[data-testid="result-title-a"], h2 a[href^="http"]'
                    );
                    if (!anchor || !anchor.href) continue;
                    let parsed;
                    try { parsed = new URL(anchor.href); } catch { continue; }
                    if (parsed.hostname.endsWith('duckduckgo.com')) continue;
                    if (seen.has(anchor.href)) continue;
                    const snippet = box.querySelector(
                      '[data-result="snippet"], [data-testid="result-snippet"], .result__snippet'
                    );
                    const title = text(anchor);
                    if (!title) continue;
                    seen.add(anchor.href);
                    out.push({title, url: anchor.href, content: text(snippet)});
                  }
                  return out;
                }
                """,
                limit,
            )
            return result if isinstance(result, list) else []
        result = await page.evaluate(
            r"""
            (limit) => {
              const text = (el) => (el?.innerText || el?.textContent || '').trim();
              const snippetSelector = [
                'div.VwiC3b', 'div[data-sncf]', 'span.aCOpRe', '[data-sncf]',
                'div[style*="-webkit-line-clamp"]', '.yXK7lf', '.ITfqId',
              ].join(', ');
              const out = [];
              const seen = new Set();
              for (const h3 of document.querySelectorAll('h3')) {
                if (out.length >= limit) break;
                const title = text(h3);
                if (!title) continue;
                const anchor = h3.closest('a[href]') || h3.querySelector('a[href]') || (h3.parentElement ? h3.parentElement.closest('a[href]') : null);
                if (!anchor || !anchor.href) continue;
                let targetUrl = anchor.href;
                let box = h3.closest('div.MjjYud, div.g, div[data-snhf], div[jscontroller], div[data-hveid]') || anchor.parentElement;
                let card = h3.closest('div.MjjYud, div.N54PNb, div.WlydOe, div.g, div.ULSxyf') || h3.parentElement;

                const unwrapUrl = (raw) => {
                  if (!raw) return null;
                  try {
                    const u = new URL(raw, 'https://www.google.com');
                    if (u.hostname.includes('google.') || u.hostname.endsWith('google.com')) {
                      const dest = u.searchParams.get('url') || u.searchParams.get('q');
                      if (dest && (dest.startsWith('http://') || dest.startsWith('https://')) && !dest.includes('google.com') && !dest.includes('google.')) {
                        return dest;
                      }
                    } else if (u.protocol === 'http:' || u.protocol === 'https:') {
                      return u.href;
                    }
                  } catch (_) {}
                  return null;
                };

                // 1. Try to unwrap real URL from the anchor's ping or href
                const directTarget = unwrapUrl(anchor.getAttribute('ping')) || unwrapUrl(anchor.href);
                if (directTarget) {
                  targetUrl = directTarget;
                } else if (targetUrl.includes('google.com/goto') || targetUrl.includes('google.com/url')) {
                  // 2. Look for any other direct or unwrappable anchor in the card container
                  if (card) {
                    for (const a of card.querySelectorAll('a[href], a[ping]')) {
                      const u = unwrapUrl(a.getAttribute('ping')) || unwrapUrl(a.href || a.getAttribute('href'));
                      if (u) {
                        targetUrl = u;
                        break;
                      }
                    }
                  }
                }

                if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) continue;
                if (seen.has(targetUrl)) continue;

                let domain = '';
                const cite = card?.querySelector('cite') || box?.querySelector('cite');
                if (cite) {
                  const citeText = text(cite);
                  if (citeText) {
                    try {
                      const firstPart = citeText.split(/\s+[›>»·•\s]\s+/)[0].trim();
                      if (firstPart.startsWith('http://') || firstPart.startsWith('https://')) {
                        domain = new URL(firstPart).hostname;
                      } else if (firstPart) {
                        const rawHost = firstPart.split('/')[0].trim();
                        if (rawHost) {
                          domain = new URL('https://' + rawHost).hostname;
                        }
                      }
                    } catch (_) {}
                  }
                }

                let snippet = box?.querySelector(snippetSelector);
                for (let depth = 0; !snippet && box && depth < 4; depth += 1) {
                  box = box.parentElement;
                  snippet = box?.querySelector(snippetSelector);
                }
                seen.add(targetUrl);
                out.push({title: title, url: targetUrl, content: text(snippet), domain: domain});
              }
              return out;
            }
            """,
            limit,
        )
        return result if isinstance(result, list) else []

    _CHALLENGE_REASONS = frozenset(
        {
            "google_challenge_url",
            "duckduckgo_challenge_url",
            "captcha",
            "consent_required",
            "unusual_traffic",
        }
    )

    def _record_blocked_result(
        self,
        request: SearchRequest,
        route: Route,
        page: Any,
        search_url: str,
        reason: str,
    ) -> dict[str, Any]:
        engine = request.engine or "google"
        challenge_url = str(getattr(page, "url", "") or search_url)
        if reason in self._CHALLENGE_REASONS:
            self._last_challenges[engine] = {
                "engine": engine,
                "route": route.name,
                "profile_key": route.profile_key,
                "locale": request.locale,
                "query": request.query,
                "search_url": search_url,
                "challenge_url": challenge_url,
                "reason": reason,
                "occurred_at": time.time(),
                "solved": False,
            }
        return {
            "ok": False,
            "status": "blocked",
            "reason": reason,
            "route": route.name,
            "challenge_url": challenge_url,
            "verify_path": f"/browser-verify?engine={engine}",
        }

    async def _perform(self, request: SearchRequest, route: Route) -> dict[str, Any]:
        started_at = time.perf_counter()
        engine = request.engine or "google"
        if engine not in self.SUPPORTED_ENGINES:
            return {
                "ok": False,
                "status": "invalid_request",
                "reason": f"unsupported_engine:{engine}",
                "route": route.name,
            }
        key_preview = self._context_key(route, request.locale, engine)
        active_verify = self._verify_session
        if (
            active_verify is not None
            and not active_verify.get("solved")
            and active_verify.get("context_key") == key_preview
        ):
            return {
                "ok": False,
                "status": "blocked",
                "reason": "verification_in_progress",
                "route": route.name,
                "verify_path": f"/browser-verify?engine={engine}",
            }
        await self._wait_route_cooldown(request, route)
        key, context = await self._context(route, request.locale, engine)
        _timing_event(request, "context_ready", route=route.name, context_key=key)
        page = await context.new_page()
        self._context_active_pages[key] = self._context_active_pages.get(key, 0) + 1
        _timing_event(
            request,
            "page_created",
            route=route.name,
            context_key=key,
            active_pages=self._context_active_pages[key],
        )
        url = (
            self._duckduckgo_url(request)
            if engine == "duckduckgo"
            else self._google_url(request)
        )
        try:
            await self._apply_page_profile(context, page, request.locale)
            navigation_started_at = time.perf_counter()
            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self.navigation_timeout,
                )
            finally:
                _timing_event(
                    request,
                    "navigation_completed",
                    elapsed_ms=_elapsed_ms(navigation_started_at),
                    route=route.name,
                )
            if response is not None and response.status == 429:
                return {
                    "ok": False,
                    "status": "rate_limited",
                    "reason": "http_429",
                    "route": route.name,
                }
            if response is not None and response.status in {401, 403}:
                return self._record_blocked_result(
                    request, route, page, url, f"http_{response.status}"
                )

            reason = await self._block_reason(page, engine)
            if reason == "consent_required":
                consent_started_at = time.perf_counter()
                dismissed = await self._dismiss_consent(page)
                _timing_event(
                    request,
                    "consent_checked",
                    elapsed_ms=_elapsed_ms(consent_started_at),
                    dismissed=dismissed,
                    route=route.name,
                )
                if dismissed:
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=1500)
                    except Exception:
                        pass
                    reason = await self._block_reason(page, engine)
            _timing_event(
                request, "block_checked", reason=reason or "", route=route.name
            )
            if reason:
                return self._record_blocked_result(request, route, page, url, reason)

            selector_started_at = time.perf_counter()
            matched = await self._wait_for_results(page, engine, self.selector_timeout)
            selector_status = "matched" if matched else "timeout_or_error"
            if not matched:
                reason = await self._block_reason(page, engine)
                if reason:
                    return self._record_blocked_result(
                        request, route, page, url, reason
                    )
            _timing_event(
                request,
                "selector_wait_completed",
                elapsed_ms=_elapsed_ms(selector_started_at),
                status=selector_status,
                route=route.name,
            )
            extract_started_at = time.perf_counter()
            results = await self._extract_results(page, engine=engine)
            _timing_event(
                request,
                "results_extracted",
                elapsed_ms=_elapsed_ms(extract_started_at),
                result_count=len(results),
                route=route.name,
            )
            if not results:
                page_text = (await self._page_text(page)).lower()
                no_results_markers = (
                    "did not match any documents",
                    "找不到和您查询的",
                    "no results found",
                    "没有找到结果",
                )
                if not any(marker in page_text for marker in no_results_markers):
                    reason = await self._block_reason(page, engine)
                    if reason:
                        return self._record_blocked_result(
                            request, route, page, url, reason
                        )
                    return self._record_blocked_result(
                        request, route, page, url, "no_results_extracted"
                    )
            await self._save_state(key, context)
            if engine == "google":
                await self._update_google_auth_after_search(page, context, results)
            return {"ok": True, "status": "ok", "route": route.name, "results": results}
        except Exception as exc:
            try:
                reason = await self._block_reason(page, request.engine or "google")
            except Exception:
                reason = None
            if reason:
                return self._record_blocked_result(request, route, page, url, reason)
            return {
                "ok": False,
                "status": "route_error",
                "reason": "transport_error" if self._is_transport_error(exc) else "error",
                "detail": str(exc),
                "route": route.name,
            }
        finally:
            await self._release_page(key, context, page)
            _timing_event(
                request,
                "perform_completed",
                elapsed_ms=_elapsed_ms(started_at),
                route=route.name,
            )

    async def _wait_route_cooldown(
        self, request: SearchRequest, route: Route
    ) -> None:
        key = self._context_key(route, request.locale, request.engine or "google")
        deadline = self._route_cooldowns.get(key, 0.0)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self._route_cooldowns.pop(key, None)
            return
        _timing_event(
            request,
            "route_cooldown_wait",
            route=route.name,
            wait_ms=round(remaining * 1000, 3),
        )
        await asyncio.sleep(remaining)
        self._route_cooldowns.pop(key, None)

    def _mark_route_cooldown(self, request: SearchRequest, route: Route) -> None:
        if self.route_cooldown_seconds <= 0:
            return
        key = self._context_key(route, request.locale, request.engine or "google")
        self._route_cooldowns[key] = time.monotonic() + self.route_cooldown_seconds

    async def _settle_route(
        self,
        request: SearchRequest,
        route: Route,
        result: dict[str, Any],
        attempts: int,
    ) -> tuple[dict[str, Any], int]:
        route_failure = result.get("status") in {
            "blocked",
            "rate_limited",
            "route_error",
        }
        if result.get("ok") or not route_failure:
            return result, attempts
        if result.get("reason") in {"javascript_required", "browser_update_required"}:
            await self._close_route(
                route,
                clear_cookies=False,
                engine=request.engine or "google",
                locale=request.locale,
                reason=result.get("reason", "route_failure"),
            )
            return result, attempts
        challenge = result.get("reason") in {
            "google_challenge_url",
            "duckduckgo_challenge_url",
            "captcha",
            "consent_required",
            "unusual_traffic",
        }
        if challenge and self.recovery_retries_per_route > 0:
            # Never retry a challenge in the same Context.  It may already
            # contain a challenge/abuse token; recreate from the last known
            # good state first, then fall back to a clean Context on the next
            # queued request if this recovery also fails.
            await self._close_route(
                route,
                clear_cookies=False,
                engine=request.engine or "google",
                locale=request.locale,
                reason="challenge_before_recovery",
            )
            if self.challenge_retry_delay:
                await asyncio.sleep(self.challenge_retry_delay)
            _timing_event(
                request,
                "route_recovery_started",
                route=route.name,
                recovery_attempt=1,
                state="last_good",
            )
            result = await self._perform(request, route)
            attempts += 1
            if result.get("ok") or result.get("status") not in {
                "blocked",
                "rate_limited",
                "route_error",
            }:
                self._route_cooldowns.pop(
                    self._context_key(
                        route, request.locale, request.engine or "google"
                    ),
                    None,
                )
                return result, attempts
            await self._close_route(
                route,
                clear_cookies=True,
                engine=request.engine or "google",
                locale=request.locale,
                reason="challenge_recovery_failed",
            )
            self._mark_route_cooldown(request, route)
            _timing_event(
                request,
                "route_recovery_failed",
                route=route.name,
                cooldown_seconds=self.route_cooldown_seconds,
                next_state="clean",
            )
            return result, attempts
        await self._close_route(
            route,
            clear_cookies=True,
            engine=request.engine or "google",
            locale=request.locale,
            reason="route_failure",
        )
        self._mark_route_cooldown(request, route)
        return result, attempts

    async def search(self, request: SearchRequest) -> dict[str, Any]:
        """Search with Context recovery, then optional proxy rotation."""

        started_at = time.perf_counter()
        await self.start()
        direct = Route("direct", "direct")
        result = await self._perform(request, direct)
        attempts = 1
        result, attempts = await self._settle_route(request, direct, result, attempts)
        routes_tried = 1
        recoveries = max(0, attempts - 1)
        route_failure = result.get("status") in {
            "blocked",
            "rate_limited",
            "route_error",
        }
        configuration_failure = result.get("reason") in {
            "javascript_required",
            "browser_update_required",
        }
        if result.get("ok") or not route_failure or configuration_failure:
            final = {
                **result,
                "attempts": attempts,
                "routes_tried": routes_tried,
                "recoveries": recoveries,
            }
            _timing_event(
                request,
                "search_completed",
                elapsed_ms=_elapsed_ms(started_at),
                attempts=attempts,
                status=result.get("status", ""),
                reason=result.get("reason", ""),
                result_count=len(result.get("results", [])),
            )
            return final
        if routes_tried >= self.max_route_attempts or not self.proxy_pool_enabled:
            final = {
                **result,
                "attempts": attempts,
                "routes_tried": routes_tried,
                "recoveries": recoveries,
            }
            _timing_event(
                request,
                "search_completed",
                elapsed_ms=_elapsed_ms(started_at),
                attempts=attempts,
                status=result.get("status", ""),
                reason=result.get("reason", ""),
                result_count=len(result.get("results", [])),
            )
            return final

        for proxy in self.proxy_pool.round():
            if routes_tried >= self.max_route_attempts:
                break
            route = Route(proxy.display_name, proxy.key, proxy)
            result = await self._perform(request, route)
            attempts += 1
            routes_tried += 1
            result, attempts = await self._settle_route(
                request, route, result, attempts
            )
            recoveries = max(0, attempts - routes_tried)
            configuration_failure = result.get("reason") in {
                "javascript_required",
                "browser_update_required",
            }
            if (
                result.get("ok")
                or result.get("status")
                not in {
                    "blocked",
                    "rate_limited",
                    "route_error",
                }
                or configuration_failure
            ):
                break
        final = {
            **result,
            "attempts": attempts,
            "routes_tried": routes_tried,
            "recoveries": recoveries,
        }
        _timing_event(
            request,
            "search_completed",
            elapsed_ms=_elapsed_ms(started_at),
            attempts=attempts,
            status=result.get("status", ""),
            reason=result.get("reason", ""),
            result_count=len(result.get("results", [])),
        )
        return final

    async def warm(self, locale: str = "zh-CN") -> None:
        await self.start()
        await self._context(Route("direct", "direct"), locale, "google")
        logger.info(
            "browser-search warmup locale=%s contexts=%s", locale, len(self._contexts)
        )

    async def reload_google_auth(
        self, *, clear_route_states: bool = False
    ) -> dict[str, Any]:
        """Discard cached Google contexts so newly imported/cleared auth takes effect."""

        if self._context_lock is not None:
            async with self._context_lock:
                google_keys = [
                    key for key in list(self._contexts) if key.startswith("google")
                ]
                for key in google_keys:
                    context = self._contexts.get(key)
                    active = self._context_active_pages.get(key, 0)
                    if active:
                        self._pending_context_close.add(key)
                        continue
                    self._contexts.pop(key, None)
                    self._context_locales.pop(key, None)
                    self._context_active_pages.pop(key, None)
                    if context is not None:
                        try:
                            await context.close()
                        except Exception:
                            logger.debug(
                                "failed to close google context %s", key, exc_info=True
                            )
                for key in [k for k in list(self._route_cooldowns) if k.startswith("google")]:
                    self._route_cooldowns.pop(key, None)
                for key in [
                    k for k in list(self._force_clean_context) if k.startswith("google")
                ]:
                    self._force_clean_context.discard(key)
        if clear_route_states:
            for candidate in self.profile_root.glob("google-*"):
                state_file = candidate / "storage-state.json"
                try:
                    state_file.unlink(missing_ok=True)
                except OSError:
                    pass
        return get_google_auth_status(self.google_auth_state_path)

    def _ensure_verify_lock(self) -> asyncio.Lock:
        if self._verify_lock is None:
            self._verify_lock = asyncio.Lock()
        return self._verify_lock

    @staticmethod
    def _is_verify_url_allowed(engine: str, url: str) -> bool:
        parsed = urlparse(str(url or "").strip())
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        if engine == "duckduckgo":
            return host == "duckduckgo.com" or host.endswith(".duckduckgo.com")
        return is_google_cookie_domain(host)

    @staticmethod
    def _is_google_results_or_exempt_url(url: str) -> bool:
        parsed = urlparse(str(url or ""))
        host = (parsed.hostname or "").lower()
        if not is_google_cookie_domain(host):
            return False
        path = parsed.path or ""
        if "/sorry/" in path or "/challenge/" in path:
            return False
        if host.startswith("consent.") or host.startswith("accounts."):
            return False
        return True

    async def _close_verify_session_locked(self) -> None:
        task = self._verify_reaper_task
        self._verify_reaper_task = None
        current = asyncio.current_task()
        if task is not None and task is not current and not task.done():
            task.cancel()
        sess = self._verify_session
        self._verify_session = None
        if not sess:
            return
        await self._release_page(sess["context_key"], sess["context"], sess["page"])

    def _schedule_verify_close(self, session_id: str, delay: float) -> None:
        task = self._verify_reaper_task
        if task is not None and not task.done():
            task.cancel()

        async def _reap() -> None:
            try:
                await asyncio.sleep(max(0.0, delay))
            except asyncio.CancelledError:
                return
            async with self._ensure_verify_lock():
                sess = self._verify_session
                if sess is None or sess.get("session_id") != session_id:
                    return
                if not sess.get("solved"):
                    idle = time.monotonic() - float(sess.get("last_activity_at", 0.0))
                    if idle < self._verify_idle_ttl:
                        self._schedule_verify_close(
                            session_id, max(1.0, self._verify_idle_ttl - idle)
                        )
                        return
                await self._close_verify_session_locked()
                logger.info(
                    "browser-search-verify-closed-automatically session_id=%s solved=%s",
                    session_id,
                    bool(sess.get("solved", False)),
                )

        self._verify_reaper_task = asyncio.create_task(_reap())

    async def _persist_verified_context(self, sess: dict[str, Any]) -> None:
        key = sess["context_key"]
        context = sess["context"]
        engine = sess["engine"]
        await self._save_state(key, context)
        self._force_clean_context.discard(key)
        self._route_cooldowns.pop(key, None)
        if engine == "google" and self.persist_google_auth and self.google_auth_state_path.exists():
            try:
                raw_state = await context.storage_state()
                if isinstance(raw_state, dict):
                    google_state = extract_google_storage_state(raw_state)
                    existing = load_google_auth_state(self.google_auth_state_path)
                    merged = merge_storage_states(existing, google_state)
                    if merged.get("cookies"):
                        save_google_auth_state(
                            self.google_auth_state_path,
                            merged,
                            source_format="refresh",
                            last_auth_ok=True if has_google_auth_cookies(merged["cookies"]) else None,
                            last_reason="manual_verify",
                        )
            except Exception:
                logger.debug("failed to refresh google auth after manual verify", exc_info=True)
        challenge = self._last_challenges.get(engine)
        if isinstance(challenge, dict):
            challenge["solved"] = True

    def _serialize_verify_status(
        self, engine: str, sess: dict[str, Any] | None
    ) -> dict[str, Any]:
        last_challenge = self._last_challenges.get(engine)
        if sess is None:
            return {
                "ok": True,
                "active": False,
                "session_id": "",
                "engine": engine,
                "route": (last_challenge or {}).get("route", "direct"),
                "current_url": "",
                "title": "",
                "reason": (last_challenge or {}).get("reason", ""),
                "solved": bool((last_challenge or {}).get("solved", False)),
                "viewport": {"width": 1280, "height": 800},
                "last_challenge": last_challenge,
            }
        return {
            "ok": True,
            "active": True,
            "session_id": sess["session_id"],
            "engine": sess["engine"],
            "route": sess["route"].name,
            "current_url": sess.get("current_url", ""),
            "title": sess.get("title", ""),
            "reason": sess.get("reason", ""),
            "solved": bool(sess.get("solved", False)),
            "viewport": {"width": 1280, "height": 800},
            "last_challenge": self._last_challenges.get(sess["engine"]),
        }

    async def _refresh_verify_state_locked(
        self, sess: dict[str, Any]
    ) -> dict[str, Any]:
        page = sess["page"]
        context = sess["context"]
        engine = sess["engine"]
        if (time.monotonic() - sess["last_activity_at"]) > self._verify_idle_ttl:
            await self._close_verify_session_locked()
            return self._serialize_verify_status(engine, None)
        if getattr(page, "is_closed", lambda: False)():
            await self._close_verify_session_locked()
            return self._serialize_verify_status(engine, None)

        current_url = str(getattr(page, "url", "") or "")
        sess["current_url"] = current_url
        try:
            sess["title"] = str(await page.title() or "")
        except Exception:
            sess["title"] = ""

        try:
            reason = await self._block_reason(page, engine)
        except Exception:
            reason = None
        sess["reason"] = reason or ""

        solved = False
        if not reason:
            if engine == "duckduckgo":
                host = (urlparse(current_url).hostname or "").lower()
                if (host == "duckduckgo.com" or host.endswith(".duckduckgo.com")) and (
                    await self._wait_for_results(page, "duckduckgo", 60)
                ):
                    solved = True
            elif self._is_google_results_or_exempt_url(current_url):
                if await self._wait_for_results(page, "google", 60):
                    solved = True
                elif "/search" in current_url:
                    try:
                        cookies = await context.cookies(["https://www.google.com"])
                        if any(
                            c.get("name") == "GOOGLE_ABUSE_EXEMPTION" and c.get("value")
                            for c in cookies
                        ):
                            solved = True
                    except Exception:
                        pass

        if solved and not sess.get("solved"):
            await self._persist_verified_context(sess)
            sess["solved"] = True
            self._schedule_verify_close(sess["session_id"], delay=3.0)
            logger.info(
                "browser-search-verify-solved engine=%s route=%s url=%s",
                engine,
                sess["route"].name,
                current_url,
            )
        return self._serialize_verify_status(engine, sess)

    def _resolve_verify_route(self, engine: str) -> tuple[Route, str, str]:
        challenge = self._last_challenges.get(engine) or {}
        locale = self._normalize_locale(challenge.get("locale"), default="zh-CN") or "zh-CN"
        profile_key = str(challenge.get("profile_key") or "direct")
        route = Route("direct", "direct")
        if profile_key != "direct" and self.proxy_pool_enabled:
            for proxy in self.proxy_pool.round():
                if proxy.key == profile_key:
                    route = Route(proxy.display_name, proxy.key, proxy)
                    break
        default_url = (
            "https://duckduckgo.com/?q=test"
            if engine == "duckduckgo"
            else f"https://www.google.com/search?q=test&gl=hk&hl={locale}"
        )
        search_url = str(challenge.get("search_url") or "")
        if not self._is_verify_url_allowed(engine, search_url):
            search_url = default_url
        return route, locale, search_url

    async def verify_status(self, engine: str = "google") -> dict[str, Any]:
        engine_name = (engine or "google").strip().lower()
        if engine_name not in self.SUPPORTED_ENGINES:
            return {"ok": False, "status": "invalid_request", "reason": f"unsupported_engine:{engine_name}"}
        async with self._ensure_verify_lock():
            sess = self._verify_session
            if sess is None:
                return self._serialize_verify_status(engine_name, None)
            if sess["engine"] != engine_name:
                return self._serialize_verify_status(engine_name, None)
            return await self._refresh_verify_state_locked(sess)

    async def verify_start(
        self, engine: str = "google", url: str | None = None, force_new: bool = False
    ) -> dict[str, Any]:
        engine_name = (engine or "google").strip().lower()
        if engine_name not in self.SUPPORTED_ENGINES:
            return {"ok": False, "status": "invalid_request", "reason": f"unsupported_engine:{engine_name}"}
        await self.start()
        async with self._ensure_verify_lock():
            existing = self._verify_session
            if (
                existing is not None
                and not force_new
                and existing["engine"] == engine_name
                and not getattr(existing["page"], "is_closed", lambda: False)()
                and (time.monotonic() - existing["last_activity_at"]) <= self._verify_idle_ttl
            ):
                if url and self._is_verify_url_allowed(engine_name, url):
                    await existing["page"].goto(
                        url, wait_until="domcontentloaded", timeout=self.navigation_timeout
                    )
                    existing["last_frame"] = None
                    existing["last_frame_at"] = 0.0
                existing["last_activity_at"] = time.monotonic()
                return await self._refresh_verify_state_locked(existing)

            if existing is not None:
                await self._close_verify_session_locked()

            route, locale, default_target = self._resolve_verify_route(engine_name)
            target_url = (
                url
                if url and self._is_verify_url_allowed(engine_name, url)
                else default_target
            )
            key = self._context_key(route, locale, engine_name)
            self._force_clean_context.discard(key)
            self._route_cooldowns.pop(key, None)
            key, context = await self._context(route, locale, engine_name)
            page = await context.new_page()
            self._context_active_pages[key] = self._context_active_pages.get(key, 0) + 1
            try:
                await self._apply_page_profile(context, page, locale)
                await page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=self.navigation_timeout,
                )
            except Exception as exc:
                await self._release_page(key, context, page)
                return {
                    "ok": False,
                    "status": "error",
                    "reason": f"verify_navigation_failed:{exc}",
                }

            sess = {
                "session_id": secrets.token_urlsafe(12),
                "engine": engine_name,
                "route": route,
                "locale": locale,
                "context_key": key,
                "context": context,
                "page": page,
                "target_url": target_url,
                "current_url": str(getattr(page, "url", "") or target_url),
                "title": "",
                "reason": "",
                "solved": False,
                "started_at": time.monotonic(),
                "last_activity_at": time.monotonic(),
                "last_frame": None,
                "last_frame_at": 0.0,
            }
            self._verify_session = sess
            self._schedule_verify_close(sess["session_id"], delay=self._verify_idle_ttl)
            return await self._refresh_verify_state_locked(sess)

    async def verify_frame(
        self, engine: str = "google", force: bool = False
    ) -> tuple[bytes, dict[str, Any]]:
        engine_name = (engine or "google").strip().lower()
        sess = self._verify_session
        if sess is None or (engine_name and sess["engine"] != engine_name):
            raise ValueError("no active verification session")
        if getattr(sess["page"], "is_closed", lambda: False)():
            async with self._ensure_verify_lock():
                await self._close_verify_session_locked()
            raise ValueError("verification session is closed")
        now = time.monotonic()
        cached = sess.get("last_frame")
        if not force and cached and (now - float(sess.get("last_frame_at", 0.0))) < 0.15:
            return cached, self._serialize_verify_status(sess["engine"], sess)
        try:
            frame = await sess["page"].screenshot(type="jpeg", quality=80)
        except Exception as exc:
            if cached:
                return cached, self._serialize_verify_status(sess["engine"], sess)
            raise ValueError(f"screenshot temporarily unavailable: {exc}") from exc
        sess["last_frame"] = frame
        sess["last_frame_at"] = now
        sess["last_activity_at"] = now
        status = self._serialize_verify_status(sess["engine"], sess)
        return frame, status

    async def verify_input(self, payload: dict[str, Any]) -> dict[str, Any]:
        engine_name = str(payload.get("engine", "google")).strip().lower()
        sess = self._verify_session
        if sess is None or (engine_name and sess["engine"] != engine_name):
            return {"ok": False, "status": "no_session", "reason": "no active verification session"}
        page = sess["page"]
        if getattr(page, "is_closed", lambda: False)():
            async with self._ensure_verify_lock():
                await self._close_verify_session_locked()
            return {"ok": False, "status": "no_session", "reason": "verification page is closed"}

        kind = str(payload.get("kind", "")).strip().lower()
        sess["last_activity_at"] = time.monotonic()
        try:
            if kind in {"click", "move", "down", "up"}:
                x = max(0, min(1279, int(round(float(payload.get("x", 0))))))
                y = max(0, min(799, int(round(float(payload.get("y", 0))))))
                button = str(payload.get("button", "left")).lower()
                if button not in {"left", "right", "middle"}:
                    button = "left"
                if kind == "click":
                    click_count = max(1, min(2, int(payload.get("click_count", 1))))
                    await page.mouse.click(x, y, button=button, click_count=click_count)
                elif kind == "move":
                    await page.mouse.move(x, y)
                elif kind == "down":
                    await page.mouse.down(button=button)
                elif kind == "up":
                    await page.mouse.up(button=button)
            elif kind == "wheel":
                dx = max(-2000, min(2000, float(payload.get("delta_x", 0))))
                dy = max(-2000, min(2000, float(payload.get("delta_y", 0))))
                await page.mouse.wheel(dx, dy)
            elif kind == "type":
                text = str(payload.get("text", ""))[:500]
                if text:
                    await page.keyboard.type(text)
            elif kind == "press":
                key = str(payload.get("key", "")).strip()[:32]
                if key:
                    await page.keyboard.press(key)
            elif kind == "reload":
                await page.reload(
                    wait_until="domcontentloaded", timeout=self.navigation_timeout
                )
            elif kind == "goto":
                url = str(payload.get("url", "")).strip()
                if not self._is_verify_url_allowed(sess["engine"], url):
                    return {"ok": False, "status": "invalid_request", "reason": "disallowed verification URL"}
                await page.goto(
                    url, wait_until="domcontentloaded", timeout=self.navigation_timeout
                )
            else:
                return {"ok": False, "status": "invalid_request", "reason": f"unsupported input kind: {kind}"}
        except Exception as exc:
            return {"ok": False, "status": "error", "reason": str(exc)}

        await asyncio.sleep(0.15)
        sess["last_frame"] = None
        sess["last_frame_at"] = 0.0
        async with self._ensure_verify_lock():
            if self._verify_session is not sess:
                return self._serialize_verify_status(engine_name, None)
            return await self._refresh_verify_state_locked(sess)

    async def verify_complete(
        self, engine: str = "google", close_session: bool = True
    ) -> dict[str, Any]:
        engine_name = (engine or "google").strip().lower()
        async with self._ensure_verify_lock():
            sess = self._verify_session
            if sess is None or (engine_name and sess["engine"] != engine_name):
                return self._serialize_verify_status(engine_name, None)
            status = await self._refresh_verify_state_locked(sess)
            await self._persist_verified_context(sess)
            status["solved"] = True
            if close_session:
                await self._close_verify_session_locked()
                status["active"] = False
            return status

    async def verify_close(self) -> dict[str, Any]:
        async with self._ensure_verify_lock():
            engine_name = (self._verify_session or {}).get("engine", "google")
            await self._close_verify_session_locked()
            return self._serialize_verify_status(engine_name, None)


class BrowserSearchDispatcher:
    """Thread-safe SearXNG facade backed by one async Chromium runtime."""

    SUPPORTED_ENGINES = BrowserSearchManager.SUPPORTED_ENGINES

    def __init__(self, config: dict[str, Any]):
        self.config = config
        try:
            configured_capacity = int(config.get("max_concurrent_pages", 2))
        except (TypeError, ValueError):
            configured_capacity = 2
        self.max_concurrent_pages = max(1, min(16, configured_capacity))
        try:
            configured_google_capacity = int(
                config.get("google_max_concurrent_pages", 1)
            )
        except (TypeError, ValueError):
            configured_google_capacity = 1
        self.google_max_concurrent_pages = max(
            1, min(16, configured_google_capacity)
        )
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="browser-search-runtime",
            daemon=True,
        )
        self._ready = threading.Event()
        self._manager: BrowserSearchManager | None = None
        self._startup_error: Exception | None = None
        self._thread.start()
        if not self._ready.wait(timeout=60):
            raise RuntimeError("browser search runtime did not start")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        manager = BrowserSearchManager(self.config)
        self._manager = manager

        async def initialize() -> None:
            if bool(self.config.get("prewarm", True)):
                try:
                    await manager.warm(str(self.config.get("prewarm_locale", "zh-CN")))
                except Exception as exc:  # keep HTTP service alive for retry
                    self._startup_error = exc
                    logger.exception("browser search warmup failed")

        try:
            self._loop.run_until_complete(initialize())
            self._ready.set()
            self._loop.run_forever()
        finally:
            try:
                self._loop.run_until_complete(manager.close())
            except Exception:
                logger.exception("browser search runtime shutdown failed")
            self._loop.close()

    async def _search(self, request: SearchRequest) -> dict[str, Any]:
        if self._manager is None:
            raise RuntimeError("browser search runtime is not initialized")
        if not hasattr(self, "_page_slots"):
            self._page_slots = asyncio.Semaphore(self.max_concurrent_pages)
            self._engine_slots = {
                "google": asyncio.Semaphore(self.google_max_concurrent_pages),
                "duckduckgo": asyncio.Semaphore(self.max_concurrent_pages),
            }
            self._active_pages = 0
        engine = (request.engine or "google").strip().lower()
        engine_slot = self._engine_slots.get(engine)
        if engine_slot is None:
            engine_slot = asyncio.Semaphore(self.max_concurrent_pages)
            self._engine_slots[engine] = engine_slot
        engine_queued_at = time.perf_counter()
        async with engine_slot:
            try:
                _timing_event(
                    request,
                    "engine_slot_acquired",
                    queue_wait_ms=round(
                        (time.perf_counter() - engine_queued_at) * 1000, 3
                    ),
                    engine_capacity=(
                        self.google_max_concurrent_pages
                        if engine == "google"
                        else self.max_concurrent_pages
                    ),
                )
                page_queued_at = time.perf_counter()
                async with self._page_slots:
                    self._active_pages += 1
                    _timing_event(
                        request,
                        "page_slot_acquired",
                        queue_wait_ms=round(
                            (time.perf_counter() - page_queued_at) * 1000, 3
                        ),
                        active_pages=self._active_pages,
                        capacity=self.max_concurrent_pages,
                    )
                    try:
                        return await self._manager.search(request)
                    finally:
                        self._active_pages -= 1
                        _timing_event(
                            request,
                            "page_slot_released",
                            active_pages=self._active_pages,
                            capacity=self.max_concurrent_pages,
                        )
            finally:
                _timing_event(
                    request,
                    "engine_slot_released",
                    engine=engine,
                    engine_capacity=(
                        self.google_max_concurrent_pages
                        if engine == "google"
                        else self.max_concurrent_pages
                    ),
                )

    def search(self, request: SearchRequest) -> dict[str, Any]:
        engine = (request.engine or "google").strip().lower()
        if engine not in self.SUPPORTED_ENGINES:
            return {
                "ok": False,
                "status": "invalid_request",
                "reason": f"unsupported_engine:{engine}",
            }
        if engine != request.engine:
            request = SearchRequest(
                query=request.query,
                pageno=request.pageno,
                locale=request.locale,
                safesearch=request.safesearch,
                time_range=request.time_range,
                engine=engine,
            )
        if not self._ready.wait(timeout=60):
            raise RuntimeError("browser search runtime is not ready")
        if self._startup_error is not None:
            logger.warning(
                "browser search warmup previously failed; retrying on demand"
            )
            self._startup_error = None
        future = asyncio.run_coroutine_threadsafe(self._search(request), self._loop)
        return future.result()

    def _call_manager(self, method: str, *args: Any, timeout: float = 30, **kwargs: Any) -> Any:
        if not self._ready.wait(timeout=60):
            raise RuntimeError("browser search runtime is not ready")
        if self._manager is None:
            raise RuntimeError("browser search runtime is not initialized")
        coro = getattr(self._manager, method)(*args, **kwargs)
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def reload_google_auth(self, *, clear_route_states: bool = False) -> dict[str, Any]:
        return self._call_manager(
            "reload_google_auth", clear_route_states=clear_route_states, timeout=30
        )

    def google_auth_status(self) -> dict[str, Any]:
        return get_google_auth_status(resolve_google_auth_path(self.config))

    def verify_status(self, engine: str = "google") -> dict[str, Any]:
        return self._call_manager("verify_status", engine, timeout=15)

    def verify_start(
        self, engine: str = "google", url: str | None = None, force_new: bool = False
    ) -> dict[str, Any]:
        return self._call_manager(
            "verify_start", engine=engine, url=url, force_new=force_new, timeout=45
        )

    def verify_frame(
        self, engine: str = "google", force: bool = False
    ) -> tuple[bytes, dict[str, Any]]:
        return self._call_manager(
            "verify_frame", engine=engine, force=force, timeout=15
        )

    def verify_input(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call_manager("verify_input", payload, timeout=30)

    def verify_complete(
        self, engine: str = "google", close_session: bool = True
    ) -> dict[str, Any]:
        return self._call_manager(
            "verify_complete", engine=engine, close_session=close_session, timeout=30
        )

    def verify_close(self) -> dict[str, Any]:
        return self._call_manager("verify_close", timeout=15)

    def close(self) -> None:
        if not self._thread.is_alive():
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=60)
