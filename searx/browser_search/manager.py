# SPDX-License-Identifier: AGPL-3.0-or-later
"""Persistent Chromium manager used by the browser search worker."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlencode
import threading

from .proxy_pool import ProxyEndpoint, ProxyPool
from .socks_bridge import Socks5AuthBridge

logger = logging.getLogger(__name__)


if sys.platform == "darwin":
    _UA_PLATFORM = "Macintosh; Intel Mac OS X 10_15_7"
elif sys.platform.startswith("win"):
    _UA_PLATFORM = "Windows NT 10.0; Win64; x64"
else:
    _UA_PLATFORM = "X11; Linux x86_64"

DEFAULT_USER_AGENT = (
    f"Mozilla/5.0 ({_UA_PLATFORM}) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

STEALTH_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', {get: () => false});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {
  get: () => [
    {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
    {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
    {name: 'Native Client', filename: 'internal-nacl-plugin'},
  ],
});
if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) {
  window.chrome.runtime = {
    connect() {},
    sendMessage() {},
    onMessage: {addListener() {}},
  };
}
delete window.__playwright;
delete window.__pw_manual;
if (navigator.permissions && navigator.permissions.query) {
  const originalQuery = navigator.permissions.query.bind(navigator.permissions);
  navigator.permissions.query = (parameters) => {
    if (parameters.name === 'notifications') {
      return Promise.resolve({state: Notification.permission, onchange: null});
    }
    return originalQuery(parameters);
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


@dataclass(frozen=True, slots=True)
class Route:
    name: str
    profile_key: str
    proxy: ProxyEndpoint | None = None


class BrowserSearchManager:
    """Run serialized browser searches with direct and proxy routes."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.profile_root = Path(
            config.get("profile_dir", "/var/lib/searxng/browser-profiles")
        )
        self.headless = bool(config.get("headless", True))
        self.browser_channel = (
            str(config.get("browser_channel", "chrome")).strip() or None
        )
        self.executable_path = str(config.get("executable_path", "")).strip() or None
        self.navigation_timeout = int(
            float(config.get("navigation_timeout", 30)) * 1000
        )
        self.selector_timeout = int(float(config.get("selector_timeout", 12)) * 1000)
        self.max_attempts = max(1, int(config.get("max_attempts", 3)))
        configured_user_agent = str(config.get("user_agent", "")).strip()
        self.user_agent = configured_user_agent or DEFAULT_USER_AGENT
        proxy_config = config.get("proxy_pool", {}) or {}
        self.proxy_pool = ProxyPool(proxy_config.get("entries", []))
        self.proxy_pool_enabled = bool(proxy_config.get("enabled", False))
        self._lock = threading.RLock()
        self._playwright: Any = None
        self._contexts: dict[str, Any] = {}
        self._socks_bridges: dict[str, Socks5AuthBridge] = {}

    def start(self) -> None:
        with self._lock:
            if self._playwright is not None:
                return
            try:
                from playwright.sync_api import sync_playwright
            except ImportError as exc:
                raise RuntimeError(
                    "browser search requires the optional Playwright dependency"
                ) from exc
            self.profile_root.mkdir(parents=True, exist_ok=True)
            self._playwright = sync_playwright().start()

    def close(self) -> None:
        with self._lock:
            for context in list(self._contexts.values()):
                try:
                    context.close()
                except Exception:  # pragma: no cover - defensive shutdown path
                    logger.exception("failed to close browser context")
            self._contexts.clear()
            for bridge in list(self._socks_bridges.values()):
                bridge.close()
            self._socks_bridges.clear()
            if self._playwright is not None:
                self._playwright.stop()
                self._playwright = None

    def _route_profile(self, route: Route) -> Path:
        path = self.profile_root / route.profile_key
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _launch_context(self, route: Route) -> Any:
        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-infobars",
                "--window-size=1280,800",
            ],
            "user_agent": self.user_agent,
            "locale": "en-US",
            "viewport": {"width": 1280, "height": 800},
        }
        if route.proxy:
            launch_kwargs["proxy"] = self._proxy_config(route.proxy)
        if self.executable_path:
            launch_kwargs["executable_path"] = self.executable_path
        elif self.browser_channel:
            launch_kwargs["channel"] = self.browser_channel

        try:
            context = self._playwright.chromium.launch_persistent_context(
                str(self._route_profile(route)), **launch_kwargs
            )
        except Exception:
            if self.browser_channel and not self.executable_path:
                launch_kwargs.pop("channel", None)
                context = self._playwright.chromium.launch_persistent_context(
                    str(self._route_profile(route)), **launch_kwargs
                )
            else:
                raise
        context.add_init_script(STEALTH_SCRIPT)
        return context

    def _proxy_config(self, proxy: ProxyEndpoint) -> dict[str, str]:
        if proxy.scheme == "socks5" and proxy.username:
            bridge = self._socks_bridges.get(proxy.key)
            if bridge is None:
                bridge = Socks5AuthBridge(proxy)
                bridge.start()
                self._socks_bridges[proxy.key] = bridge
            return bridge.playwright_config()
        return proxy.playwright_config()

    def _context(self, route: Route, fresh: bool = False) -> Any:
        if fresh and route.profile_key in self._contexts:
            self._close_route(route)
        context = self._contexts.get(route.profile_key)
        if context is None:
            context = self._launch_context(route)
            self._contexts[route.profile_key] = context
        return context

    def _close_route(self, route: Route, clear_cookies: bool = True) -> None:
        context = self._contexts.pop(route.profile_key, None)
        if context is None:
            return
        if clear_cookies:
            try:
                context.clear_cookies()
            except Exception:
                logger.debug(
                    "failed to clear cookies for route %s", route.name, exc_info=True
                )
        try:
            context.close()
        except Exception:
            logger.debug("failed to close route %s", route.name, exc_info=True)

    @staticmethod
    def _google_url(request: SearchRequest) -> str:
        params: dict[str, str] = {
            "q": request.query,
            "num": "10",
            "hl": request.locale.split("-")[0] if request.locale else "en",
            "filter": "0",
        }
        if request.pageno > 1:
            params["start"] = str((request.pageno - 1) * 10)
        if request.safesearch:
            params["safe"] = "active"
        if request.time_range in {"day", "week", "month", "year"}:
            params["tbs"] = f"qdr:{request.time_range[0]}"
        return "https://www.google.com/search?" + urlencode(params)

    @staticmethod
    def _page_text(page: Any) -> str:
        try:
            return str(page.locator("body").inner_text(timeout=3000))[:12000]
        except Exception:
            return ""

    @classmethod
    def _block_reason(cls, page: Any) -> str | None:
        url = str(getattr(page, "url", "")).lower()
        text = cls._page_text(page).lower()
        if any(marker in url for marker in ("/sorry/", "captcha", "consent.google")):
            return "google_challenge_url"
        checks = (
            ("unusual traffic", "unusual_traffic"),
            ("our systems have detected unusual traffic", "unusual_traffic"),
            ("enable javascript", "javascript_required"),
            ("update your browser", "browser_update_required"),
            ("i'm not a robot", "captcha"),
            ("recaptcha", "captcha"),
        )
        for marker, reason in checks:
            if marker in text:
                return reason
        return None

    @staticmethod
    def _dismiss_consent(page: Any) -> None:
        selectors = (
            'button:has-text("Accept all")',
            'button:has-text("I agree")',
            'button:has-text("同意")',
        )
        for selector in selectors:
            try:
                button = page.locator(selector).first
                if button.is_visible(timeout=500):
                    button.click(timeout=1000)
                    return
            except Exception:
                continue

    @staticmethod
    def _extract_results(page: Any, limit: int = 10) -> list[dict[str, str]]:
        return page.evaluate(
            """
            (limit) => {
              const text = (el) => (el?.innerText || el?.textContent || '').trim();
              const snippetSelector = [
                'div.VwiC3b',
                'div[data-sncf]',
                'span.aCOpRe',
                '[data-sncf]',
                'div[style*="-webkit-line-clamp"]',
              ].join(', ');
              const out = [];
              const seen = new Set();
              for (const h3 of document.querySelectorAll('h3')) {
                if (out.length >= limit) break;
                const anchor = h3.closest('a[href^="http"]') || h3.parentElement?.closest('a[href^="http"]');
                if (!anchor || !anchor.href) continue;
                let parsed;
                try { parsed = new URL(anchor.href); } catch { continue; }
                if (parsed.hostname.endsWith('google.com')) continue;
                if (seen.has(anchor.href)) continue;
                let box = h3.closest('div.MjjYud, div.g, div[data-snhf]') || anchor.parentElement;
                let snippet = box?.querySelector(snippetSelector);
                for (let depth = 0; !snippet && box && depth < 4; depth += 1) {
                  box = box.parentElement;
                  snippet = box?.querySelector(snippetSelector);
                }
                seen.add(anchor.href);
                out.push({title: text(h3), url: anchor.href, content: text(snippet)});
              }
              return out;
            }
            """,
            limit,
        )

    def _perform(
        self, request: SearchRequest, route: Route, fresh: bool = False
    ) -> dict[str, Any]:
        context = self._context(route, fresh=fresh)
        page = context.new_page()
        try:
            response = page.goto(
                self._google_url(request),
                wait_until="domcontentloaded",
                timeout=self.navigation_timeout,
            )
            if response is not None and response.status == 429:
                return {
                    "ok": False,
                    "status": "rate_limited",
                    "reason": "http_429",
                    "route": route.name,
                }
            if response is not None and response.status in {401, 403}:
                return {
                    "ok": False,
                    "status": "blocked",
                    "reason": f"http_{response.status}",
                    "route": route.name,
                }
            self._dismiss_consent(page)
            reason = self._block_reason(page)
            if reason:
                return {
                    "ok": False,
                    "status": "blocked",
                    "reason": reason,
                    "route": route.name,
                }
            try:
                page.wait_for_selector(
                    "div#search h3, div#rso h3", timeout=self.selector_timeout
                )
            except Exception:
                reason = self._block_reason(page)
                if reason:
                    return {
                        "ok": False,
                        "status": "blocked",
                        "reason": reason,
                        "route": route.name,
                    }
            results = self._extract_results(page)
            if not results:
                page_text = self._page_text(page).lower()
                no_results_markers = ("did not match any documents", "找不到和您查询的")
                if not any(marker in page_text for marker in no_results_markers):
                    return {
                        "ok": False,
                        "status": "error",
                        "reason": "no_results_extracted",
                        "route": route.name,
                    }
            return {"ok": True, "status": "ok", "route": route.name, "results": results}
        except Exception as exc:
            reason = self._block_reason(page)
            if reason:
                return {
                    "ok": False,
                    "status": "blocked",
                    "reason": reason,
                    "route": route.name,
                }
            return {
                "ok": False,
                "status": "error",
                "reason": str(exc),
                "route": route.name,
            }
        finally:
            try:
                page.close()
            except Exception:
                pass

    def search(self, request: SearchRequest) -> dict[str, Any]:
        """Search once, rotating routes only after a recognized block."""

        with self._lock:

            def finish(result: dict[str, Any], attempts: int) -> dict[str, Any]:
                return {**result, "attempts": attempts}

            def recoverable(result: dict[str, Any]) -> bool:
                return result.get("status") in {"blocked", "rate_limited"}

            self.start()
            direct = Route("direct", "google-direct")
            result = self._perform(request, direct)
            attempts = 1
            if result.get("ok") or not recoverable(result):
                return finish(result, attempts)

            self._close_route(direct)
            if attempts >= self.max_attempts:
                return finish(result, attempts)

            result = self._perform(request, direct, fresh=True)
            attempts += 1
            if result.get("ok") or not recoverable(result):
                return finish(result, attempts)

            self._close_route(direct)
            if not self.proxy_pool_enabled:
                return finish(result, attempts)

            last_route: Route | None = None
            for proxy in self.proxy_pool.round():
                if attempts >= self.max_attempts:
                    break
                route = Route(proxy.display_name, proxy.key, proxy)
                last_route = route
                self._close_route(route)
                result = self._perform(request, route, fresh=True)
                attempts += 1
                if result.get("ok") or not recoverable(result):
                    return finish(result, attempts)
                self._close_route(route)
            if last_route is not None:
                self._close_route(last_route)
            return finish(result, attempts)
