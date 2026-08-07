# SPDX-License-Identifier: AGPL-3.0-or-later
"""Persistent Chromium manager used by the browser search worker."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path
import queue
import time
from typing import Any
from urllib.parse import urlencode
import threading

from .proxy_pool import ProxyEndpoint, ProxyPool
from .socks_bridge import Socks5AuthBridge

logger = logging.getLogger(__name__)

BROWSER_ARGS = (
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-infobars",
    "--window-size=1280,800",
)


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
        try:
            configured_retry_delay = float(config.get("challenge_retry_delay", 2))
        except (TypeError, ValueError):
            configured_retry_delay = 2.0
        self.challenge_retry_delay = max(0.0, min(10.0, configured_retry_delay))
        configured_user_agent = str(config.get("user_agent", "")).strip()
        self.user_agent = configured_user_agent or None
        self._resolved_user_agent = self.user_agent
        self._user_agent_checked = self.user_agent is not None
        proxy_config = config.get("proxy_pool", {}) or {}
        self.proxy_pool = ProxyPool(proxy_config.get("entries", []))
        self.proxy_pool_enabled = bool(proxy_config.get("enabled", False))
        self._lock = threading.RLock()
        self._playwright: Any = None
        self._contexts: dict[str, Any] = {}
        self._context_locales: dict[str, str] = {}
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
            self._context_locales.clear()
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

    @staticmethod
    def _normalize_locale(value: str | None) -> str:
        locale = str(value or "").strip().replace("_", "-")
        if not locale or locale.lower() in {"all", "auto"}:
            return "en-US"
        parts = locale.split("-")
        if not parts[0].isalpha() or len(parts[0]) not in {2, 3}:
            return "en-US"
        normalized = [parts[0].lower()]
        for part in parts[1:]:
            if not part.isalnum() or not 2 <= len(part) <= 8:
                return "en-US"
            if len(part) == 2 and part.isalpha():
                normalized.append(part.upper())
            elif len(part) == 4 and part.isalpha():
                normalized.append(part.title())
            else:
                normalized.append(part)
        return "-".join(normalized)

    def _launch_context(self, route: Route, locale: str) -> Any:
        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": list(BROWSER_ARGS),
            "locale": locale,
            "viewport": {"width": 1280, "height": 800},
        }
        user_agent = self._effective_user_agent()
        if user_agent:
            launch_kwargs["user_agent"] = user_agent
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
        return context

    def _effective_user_agent(self) -> str | None:
        if self._user_agent_checked:
            return self._resolved_user_agent
        self._user_agent_checked = True
        if not self.headless:
            return None

        launch_kwargs: dict[str, Any] = {
            "headless": True,
            "args": list(BROWSER_ARGS),
        }
        if self.executable_path:
            launch_kwargs["executable_path"] = self.executable_path
        elif self.browser_channel:
            launch_kwargs["channel"] = self.browser_channel

        browser = None
        try:
            try:
                browser = self._playwright.chromium.launch(**launch_kwargs)
            except Exception:
                if self.browser_channel and not self.executable_path:
                    launch_kwargs.pop("channel", None)
                    browser = self._playwright.chromium.launch(**launch_kwargs)
                else:
                    raise
            page = browser.new_page()
            native_user_agent = str(page.evaluate("navigator.userAgent") or "").strip()
            self._resolved_user_agent = (
                native_user_agent.replace("HeadlessChrome/", "Chrome/") or None
            )
        except Exception:
            logger.warning(
                "failed to detect the browser user agent; using its native value",
                exc_info=True,
            )
            self._resolved_user_agent = None
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    logger.debug(
                        "failed to close user-agent probe browser", exc_info=True
                    )
        return self._resolved_user_agent

    def _proxy_config(self, proxy: ProxyEndpoint) -> dict[str, str]:
        if proxy.scheme == "socks5" and proxy.username:
            bridge = self._socks_bridges.get(proxy.key)
            if bridge is None:
                bridge = Socks5AuthBridge(proxy)
                bridge.start()
                self._socks_bridges[proxy.key] = bridge
            return bridge.playwright_config()
        return proxy.playwright_config()

    def _context(self, route: Route, locale: str, fresh: bool = False) -> Any:
        locale = self._normalize_locale(locale)
        context = self._contexts.get(route.profile_key)
        if context is not None and (
            fresh or self._context_locales.get(route.profile_key) != locale
        ):
            self._close_route(route, clear_cookies=fresh)
            context = None
        if context is None:
            context = self._launch_context(route, locale)
            self._contexts[route.profile_key] = context
            self._context_locales[route.profile_key] = locale
        return context

    def _close_route(self, route: Route, clear_cookies: bool = False) -> None:
        context = self._contexts.pop(route.profile_key, None)
        self._context_locales.pop(route.profile_key, None)
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
        locale = BrowserSearchManager._normalize_locale(request.locale)
        params: dict[str, str] = {
            "q": request.query,
            "num": "10",
            "hl": locale.split("-")[0],
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
    def _duckduckgo_url(request: SearchRequest) -> str:
        """Build the JavaScript search page URL used by the browser worker."""

        locale = BrowserSearchManager._normalize_locale(request.locale)
        params: dict[str, str] = {
            "q": request.query,
            "kl": locale.lower(),
            # DuckDuckGo uses -2 for off, -1 for moderate and 1 for strict.
            "kp": {0: "-2", 1: "-1", 2: "1"}.get(request.safesearch, "-2"),
        }
        if request.pageno > 1:
            # The browser page accepts the same offset parameter as its web UI.
            params["s"] = str((request.pageno - 1) * 10)
        if request.time_range in {"day", "week", "month", "year"}:
            params["df"] = request.time_range[0]
        return "https://duckduckgo.com/?" + urlencode(params)

    @staticmethod
    def _page_text(page: Any) -> str:
        try:
            return str(page.locator("body").inner_text(timeout=3000))[:12000]
        except Exception:
            return ""

    @classmethod
    def _block_reason(cls, page: Any, engine: str = "google") -> str | None:
        url = str(getattr(page, "url", "")).lower()
        text = cls._page_text(page).lower()
        if engine == "duckduckgo":
            if any(marker in url for marker in ("/anomaly", "/challenge", "captcha")):
                return "duckduckgo_challenge_url"
            checks = (
                ("unfortunately, bots use duckduckgo too", "captcha"),
                ("please complete the following challenge", "captcha"),
                ("are you a robot", "captcha"),
                ("检测到异常流量", "unusual_traffic"),
                ("验证您不是机器人", "captcha"),
                ("enable javascript", "javascript_required"),
                ("update your browser", "browser_update_required"),
            )
            for marker, reason in checks:
                if marker in text:
                    return reason
            for selector in (
                "#anomaly-modal",
                "form#challenge-form",
                "iframe[src*='captcha']",
                "[data-testid='challenge']",
            ):
                try:
                    if page.locator(selector).count() > 0:
                        return "captcha"
                except Exception:
                    continue
            return None
        if any(marker in url for marker in ("/sorry/", "/challenge/", "captcha")):
            return "google_challenge_url"
        if "consent.google" in url:
            return "consent_required"
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
        for marker, reason in checks:
            if marker in text:
                return reason
        for selector in (
            "form#captcha-form",
            "iframe[src*='recaptcha']",
            "iframe[src*='captcha']",
            "[id*='captcha']",
        ):
            try:
                if page.locator(selector).count() > 0:
                    return "captcha"
            except Exception:
                continue
        return None

    @staticmethod
    def _dismiss_consent(page: Any) -> None:
        selectors = (
            'button:has-text("Accept all")',
            'button:has-text("I agree")',
            'button:has-text("同意")',
            'button:has-text("接受全部")',
            'button:has-text("全部接受")',
            '[aria-label="Accept all"]',
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
    def _extract_results(
        page: Any, limit: int = 10, engine: str = "google"
    ) -> list[dict[str, str]]:
        if engine == "duckduckgo":
            return page.evaluate(
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

    def _perform(
        self, request: SearchRequest, route: Route, fresh: bool = False
    ) -> dict[str, Any]:
        context = self._context(route, request.locale, fresh=fresh)
        page = context.new_page()
        try:
            engine = request.engine or "google"
            if engine not in {"google", "duckduckgo"}:
                return {
                    "ok": False,
                    "status": "invalid_request",
                    "reason": f"unsupported_engine:{engine}",
                    "route": route.name,
                }
            url = (
                self._duckduckgo_url(request)
                if engine == "duckduckgo"
                else self._google_url(request)
            )
            response = page.goto(
                url,
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
            reason = self._block_reason(page, engine)
            if reason:
                return {
                    "ok": False,
                    "status": "blocked",
                    "reason": reason,
                    "route": route.name,
                }
            try:
                page.wait_for_selector(
                    (
                        "article[data-testid='result'], [data-testid='mainline'] article, "
                        "article"
                        if engine == "duckduckgo"
                        else "div#search h3, div#rso h3"
                    ),
                    timeout=self.selector_timeout,
                )
            except Exception:
                reason = self._block_reason(page, engine)
                if reason:
                    return {
                        "ok": False,
                        "status": "blocked",
                        "reason": reason,
                        "route": route.name,
                    }
            results = self._extract_results(page, engine=engine)
            if not results:
                page_text = self._page_text(page).lower()
                no_results_markers = (
                    "did not match any documents",
                    "找不到和您查询的",
                    "no results found",
                    "没有找到结果",
                )
                if not any(marker in page_text for marker in no_results_markers):
                    return {
                        "ok": False,
                        "status": "error",
                        "reason": "no_results_extracted",
                        "route": route.name,
                    }
            return {"ok": True, "status": "ok", "route": route.name, "results": results}
        except Exception as exc:
            reason = self._block_reason(page, request.engine or "google")
            if reason:
                return {
                    "ok": False,
                    "status": "blocked",
                    "reason": reason,
                    "route": route.name,
                }
            if self._is_transport_error(exc):
                return {
                    "ok": False,
                    "status": "route_error",
                    "reason": "transport_error",
                    "detail": str(exc),
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
        """Search while preserving a route once before cleaning or rotating."""

        with self._lock:

            def finish(result: dict[str, Any], attempts: int) -> dict[str, Any]:
                return {**result, "attempts": attempts}

            def route_failure(result: dict[str, Any]) -> bool:
                return result.get("status") in {
                    "blocked",
                    "rate_limited",
                    "route_error",
                }

            def challenge(result: dict[str, Any]) -> bool:
                return result.get("reason") in {
                    "google_challenge_url",
                    "duckduckgo_challenge_url",
                    "captcha",
                    "consent_required",
                    "unusual_traffic",
                }

            def browser_configuration_failure(result: dict[str, Any]) -> bool:
                return result.get("reason") in {
                    "javascript_required",
                    "browser_update_required",
                }

            def settle_route(
                route: Route, result: dict[str, Any], attempts: int
            ) -> tuple[dict[str, Any], int]:
                if result.get("ok") or not route_failure(result):
                    return result, attempts
                if browser_configuration_failure(result):
                    self._close_route(route, clear_cookies=False)
                    return result, attempts
                if challenge(result) and attempts < self.max_attempts:
                    if self.challenge_retry_delay:
                        time.sleep(self.challenge_retry_delay)
                    result = self._perform(request, route)
                    attempts += 1
                    if result.get("ok") or not route_failure(result):
                        return result, attempts
                    if challenge(result):
                        self._close_route(route, clear_cookies=True)
                    else:
                        self._close_route(route, clear_cookies=False)
                    return result, attempts
                self._close_route(route, clear_cookies=False)
                return result, attempts

            self.start()
            engine = request.engine or "google"
            direct = Route("direct", f"{engine}-direct")
            result = self._perform(request, direct)
            attempts = 1
            result, attempts = settle_route(direct, result, attempts)
            if (
                result.get("ok")
                or not route_failure(result)
                or browser_configuration_failure(result)
            ):
                return finish(result, attempts)
            if attempts >= self.max_attempts:
                return finish(result, attempts)

            if not self.proxy_pool_enabled:
                return finish(result, attempts)

            for proxy in self.proxy_pool.round():
                if attempts >= self.max_attempts:
                    break
                route = Route(proxy.display_name, f"{engine}-{proxy.key}", proxy)
                result = self._perform(request, route)
                attempts += 1
                result, attempts = settle_route(route, result, attempts)
                if (
                    result.get("ok")
                    or not route_failure(result)
                    or browser_configuration_failure(result)
                ):
                    return finish(result, attempts)
            return finish(result, attempts)


class _BrowserSearchLane:
    """Own one synchronous Playwright manager on one dedicated thread."""

    def __init__(self, config: dict[str, Any], engine: str):
        self._queue: queue.Queue[Any] = queue.Queue()
        self._thread = threading.Thread(
            target=self._run,
            name=f"browser-search-{engine}",
            daemon=True,
        )
        self._config = config
        self.engine = engine
        self._thread.start()

    def _run(self) -> None:
        manager: BrowserSearchManager | None = None
        try:
            manager = BrowserSearchManager(self._config)
            while True:
                item = self._queue.get()
                if item is None:
                    break
                request, event, result = item
                try:
                    result.append(manager.search(request))
                except Exception as exc:  # pragma: no cover - service boundary
                    logger.exception("browser search lane failed")
                    result.append(
                        {
                            "ok": False,
                            "status": "error",
                            "reason": str(exc),
                        }
                    )
                finally:
                    event.set()
        finally:
            if manager is not None:
                manager.close()

    def search(self, request: SearchRequest) -> dict[str, Any]:
        event = threading.Event()
        result: list[dict[str, Any]] = []
        self._queue.put((request, event, result))
        event.wait()
        return result[0]

    def close(self) -> None:
        if self._thread.is_alive():
            self._queue.put(None)
            self._thread.join(timeout=30)


class BrowserSearchDispatcher:
    """Dispatch independent search engines to independent browser lanes."""

    SUPPORTED_ENGINES = frozenset({"google", "duckduckgo"})

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._lanes: dict[str, _BrowserSearchLane] = {}
        self._lock = threading.RLock()

    def _lane(self, engine: str) -> _BrowserSearchLane:
        with self._lock:
            lane = self._lanes.get(engine)
            if lane is None:
                lane = _BrowserSearchLane(self.config, engine)
                self._lanes[engine] = lane
            return lane

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
        return self._lane(engine).search(request)

    def close(self) -> None:
        with self._lock:
            lanes = list(self._lanes.values())
            self._lanes.clear()
        for lane in lanes:
            lane.close()
