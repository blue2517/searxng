# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,missing-class-docstring

import asyncio
from pathlib import Path
import tempfile
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, Mock
from socketserver import ThreadingMixIn

from searx.browser_search.manager import (
    BrowserSearchDispatcher,
    BrowserSearchManager,
    Route,
    SearchRequest,
)
from searx.browser_search.proxy_pool import ProxyEndpoint, ProxyPool
from searx.browser_search.socks_bridge import Socks5AuthBridge
from searx.browser_search.server import BrowserSearchHTTPServer
from searx.engines import duckduckgo_browser, google_browser


class ProxyPoolTests(TestCase):

    def test_parse_proxy_keeps_credentials_out_of_display_name(self):
        proxy = ProxyEndpoint.parse(0, "socks5://user:p%40ss@example.test:1080")
        self.assertEqual("example.test", proxy.host)
        self.assertEqual("p@ss", proxy.password)
        self.assertEqual("socks5://example.test:1080", proxy.display_name)
        self.assertEqual(
            {
                "server": "socks5://example.test:1080",
                "username": "user",
                "password": "p@ss",
            },
            proxy.playwright_config(),
        )

    def test_round_rotates_and_uses_each_entry_once(self):
        pool = ProxyPool(
            ["socks5://a.test:1", "socks5://b.test:2", "socks5://c.test:3"]
        )
        self.assertEqual(
            ["a.test", "b.test", "c.test"], [item.host for item in pool.round()]
        )
        self.assertEqual(
            ["b.test", "c.test", "a.test"], [item.host for item in pool.round()]
        )


class BrowserManagerTests(IsolatedAsyncioTestCase):

    def test_default_user_agent_is_deferred_to_single_browser_context(self):
        manager = BrowserSearchManager({})
        self.assertIsNone(manager.user_agent)
        self.assertIsNone(manager._resolved_user_agent)

    def test_explicit_user_agent_is_preserved(self):
        manager = BrowserSearchManager({"user_agent": "custom-agent"})
        self.assertEqual("custom-agent", manager.user_agent)

    def test_default_channel_prefers_system_chrome(self):
        manager = BrowserSearchManager({})
        self.assertEqual("chrome", manager.browser_channel)

    def test_authenticated_socks_proxy_uses_local_bridge(self):
        manager = BrowserSearchManager({})
        manager._socks_bridges = {"proxy": Mock()}
        proxy = ProxyEndpoint.parse(0, "socks5://user:pass@example.test:1080")
        manager._socks_bridges[proxy.key] = Socks5AuthBridge(proxy)
        bridge = manager._socks_bridges[proxy.key]
        bridge.playwright_config = Mock(return_value={"server": "socks5://127.0.0.1:1"})
        self.assertEqual(
            {"server": "socks5://127.0.0.1:1"}, manager._proxy_config(proxy)
        )

    def test_google_url_encodes_query_and_filters(self):
        url = BrowserSearchManager._google_url(
            SearchRequest(
                "卡莲 奥尔黛西亚",
                pageno=2,
                locale="zh-CN",
                safesearch=1,
                time_range="week",
            )
        )
        self.assertIn(
            "q=%E5%8D%A1%E8%8E%B2+%E5%A5%A5%E5%B0%94%E9%BB%9B%E8%A5%BF%E4%BA%9A", url
        )
        self.assertIn("gl=us", url)
        self.assertIn("hl=zh-CN", url)
        self.assertIn("start=10", url)
        self.assertIn("safe=active", url)
        self.assertIn("tbs=qdr%3Aw", url)

    def test_duckduckgo_url_encodes_query_and_filters(self):
        url = BrowserSearchManager._duckduckgo_url(
            SearchRequest(
                "卡莲 奥尔黛西亚",
                pageno=2,
                locale="zh-CN",
                safesearch=2,
                time_range="week",
                engine="duckduckgo",
            )
        )
        self.assertIn(
            "q=%E5%8D%A1%E8%8E%B2+%E5%A5%A5%E5%B0%94%E9%BB%9B%E8%A5%BF%E4%BA%9A", url
        )
        self.assertIn("kl=zh-cn", url)
        self.assertIn("kp=1", url)
        self.assertIn("s=10", url)
        self.assertIn("df=w", url)

    def test_locale_normalization(self):
        self.assertEqual("zh-CN", BrowserSearchManager._normalize_locale("zh_cn"))
        self.assertEqual(
            "zh-Hant-TW", BrowserSearchManager._normalize_locale("zh-hant-tw")
        )
        self.assertEqual("", BrowserSearchManager._normalize_locale("all"))
        self.assertEqual("en-US", BrowserSearchManager._normalize_locale("all", default="en-US"))

    def test_context_key_reuses_direct_context_across_locales(self):
        manager = BrowserSearchManager({})
        self.assertEqual(
            manager._context_key(Route("direct", "direct"), "zh-CN"),
            manager._context_key(Route("direct", "direct"), "en-US"),
        )
        self.assertNotEqual(
            manager._context_key(Route("direct", "direct"), "zh-CN", "google"),
            manager._context_key(Route("direct", "direct"), "zh-CN", "duckduckgo"),
        )

    def test_proxy_context_separates_locale_when_reuse_is_disabled(self):
        manager = BrowserSearchManager({"reuse_context_locale": False})
        route = Route("proxy", "proxy-key")
        self.assertNotEqual(
            manager._context_key(route, "zh-CN"),
            manager._context_key(route, "en-US"),
        )

    async def test_force_clean_context_does_not_seed_last_good_state(self):
        manager = BrowserSearchManager({"profile_dir": "unused"})
        # Use a temporary profile without relying on a running Playwright browser.
        manager.profile_root = Path(tempfile.mkdtemp())
        manager._browser = Mock()
        manager._browser.new_context = AsyncMock(return_value=Mock())
        manager._browser.new_context.return_value.add_init_script = AsyncMock()
        manager._direct_context = Mock()
        manager._direct_context.storage_state = AsyncMock()
        route = Route("direct", "direct")
        key = manager._context_key(route, "en-US")
        manager._state_path(key).write_text("{}", encoding="utf-8")
        manager._force_clean_context.add(key)

        await manager._create_context(route, "en-US", key)

        kwargs = manager._browser.new_context.await_args.kwargs
        self.assertNotIn("storage_state", kwargs)
        manager._direct_context.storage_state.assert_not_awaited()
        self.assertNotIn(key, manager._force_clean_context)

    async def test_block_reason_detects_javascript_page(self):
        page = Mock()
        page.url = "https://www.google.com/search?q=test"
        page.evaluate = AsyncMock(
            return_value={
                "text": "Enable JavaScript to continue",
                "matches": [False] * 4,
            }
        )
        self.assertEqual(
            "javascript_required", await BrowserSearchManager._block_reason(page)
        )

    async def test_block_reason_detects_localized_challenge_and_captcha_dom(self):
        page = Mock()
        page.url = "https://www.google.com/search?q=test"
        page.evaluate = AsyncMock(
            return_value={"text": "检测到异常流量", "matches": [False] * 4}
        )
        self.assertEqual(
            "unusual_traffic", await BrowserSearchManager._block_reason(page)
        )

        page.evaluate = AsyncMock(
            return_value={"text": "", "matches": [True, False, False, False]}
        )
        self.assertEqual("captcha", await BrowserSearchManager._block_reason(page))

    async def test_duckduckgo_block_reason_detects_bot_challenge(self):
        page = Mock()
        page.url = "https://duckduckgo.com/?q=test"
        page.evaluate = AsyncMock(
            return_value={
                "text": "Unfortunately, bots use DuckDuckGo too.",
                "matches": [False] * 4,
            }
        )
        self.assertEqual(
            "captcha", await BrowserSearchManager._block_reason(page, "duckduckgo")
        )

    async def test_duckduckgo_extractor_uses_rendered_page(self):
        page = Mock()
        page.evaluate = AsyncMock(
            return_value=[
                {"title": "Title", "url": "https://example.test", "content": "Snippet"}
            ]
        )
        results = await BrowserSearchManager._extract_results(page, engine="duckduckgo")
        self.assertEqual("https://example.test", results[0]["url"])
        page.evaluate.assert_called_once()

    def test_challenge_retry_delay_is_bounded(self):
        self.assertEqual(
            10,
            BrowserSearchManager({"challenge_retry_delay": 99}).challenge_retry_delay,
        )
        self.assertEqual(
            0, BrowserSearchManager({"challenge_retry_delay": -1}).challenge_retry_delay
        )

    async def test_search_recreates_context_before_challenge_recovery(self):
        manager = BrowserSearchManager(
            {"profile_dir": "unused", "max_attempts": 3, "challenge_retry_delay": 0}
        )
        manager.start = AsyncMock()
        manager._close_route = AsyncMock()
        manager._perform = AsyncMock(
            side_effect=[
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": True, "status": "ok", "results": []},
            ]
        )

        result = await manager.search(SearchRequest("test"))

        self.assertTrue(result["ok"])
        self.assertEqual(2, result["attempts"])
        self.assertEqual(2, manager._perform.call_count)
        self.assertEqual(
            [call.args[1].name for call in manager._perform.call_args_list],
            ["direct", "direct"],
        )
        manager._close_route.assert_awaited_once_with(
            Route("direct", "direct"),
            clear_cookies=False,
            engine="google",
            locale="en-US",
            reason="challenge_before_recovery",
        )

    async def test_search_retries_direct_then_rotates_proxy(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "max_attempts": 5,
                "challenge_retry_delay": 0,
                "proxy_pool": {
                    "enabled": True,
                    "entries": ["socks5://a.test:1080", "socks5://b.test:1080"],
                },
            }
        )
        manager.start = AsyncMock()
        manager._close_route = AsyncMock()
        manager._perform = AsyncMock(
            side_effect=[
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": True, "status": "ok", "results": []},
            ]
        )
        result = await manager.search(SearchRequest("test"))
        self.assertTrue(result["ok"])
        self.assertEqual(5, result["attempts"])
        self.assertEqual(5, manager._perform.call_count)
        routes = [call.args[1].name for call in manager._perform.call_args_list]
        self.assertEqual(
            [
                "direct",
                "direct",
                "socks5://a.test:1080",
                "socks5://a.test:1080",
                "socks5://b.test:1080",
            ],
            routes,
        )
        self.assertTrue(manager._close_route.await_count >= 1)

    async def test_search_clears_route_after_rate_limit(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "max_attempts": 2,
                "proxy_pool": {
                    "enabled": True,
                    "entries": ["socks5://a.test:1080"],
                },
            }
        )
        manager.start = AsyncMock()
        manager._close_route = AsyncMock()
        manager._perform = AsyncMock(
            side_effect=[
                {"ok": False, "status": "rate_limited", "reason": "http_429"},
                {"ok": True, "status": "ok", "results": []},
            ]
        )
        result = await manager.search(SearchRequest("test"))
        self.assertTrue(result["ok"])
        self.assertEqual(2, result["attempts"])
        self.assertTrue(manager._close_route.await_count >= 1)
        first_close = manager._close_route.await_args_list[0]
        self.assertTrue(first_close.kwargs["clear_cookies"])
        self.assertEqual("route_failure", first_close.kwargs["reason"])

    async def test_browser_configuration_failure_does_not_rotate_proxy(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "max_attempts": 3,
                "proxy_pool": {
                    "enabled": True,
                    "entries": ["socks5://a.test:1080"],
                },
            }
        )
        manager.start = AsyncMock()
        manager._close_route = AsyncMock()
        manager._perform = AsyncMock(
            return_value={
                "ok": False,
                "status": "blocked",
                "reason": "browser_update_required",
            }
        )

        result = await manager.search(SearchRequest("test"))

        self.assertFalse(result["ok"])
        self.assertEqual(1, result["attempts"])
        manager._perform.assert_called_once()
        manager._close_route.assert_awaited_once_with(
            Route("direct", "direct"),
            clear_cookies=False,
            engine="google",
            locale="en-US",
            reason="browser_update_required",
        )

    async def test_transport_error_rotates_after_clean_context_reset(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "max_attempts": 2,
                "proxy_pool": {
                    "enabled": True,
                    "entries": ["socks5://a.test:1080"],
                },
            }
        )
        manager.start = AsyncMock()
        manager._close_route = AsyncMock()
        manager._perform = AsyncMock(
            side_effect=[
                {
                    "ok": False,
                    "status": "route_error",
                    "reason": "transport_error",
                },
                {"ok": True, "status": "ok", "results": []},
            ]
        )

        result = await manager.search(SearchRequest("test"))

        self.assertTrue(result["ok"])
        self.assertEqual(2, result["attempts"])
        self.assertEqual(
            [call.args[1].name for call in manager._perform.call_args_list],
            ["direct", "socks5://a.test:1080"],
        )
        manager._close_route.assert_awaited_once_with(
            Route("direct", "direct"),
            clear_cookies=True,
            engine="google",
            locale="en-US",
            reason="route_failure",
        )


class BrowserServerTests(TestCase):

    def test_http_server_accepts_parallel_lane_requests(self):
        self.assertTrue(issubclass(BrowserSearchHTTPServer, ThreadingMixIn))


class BrowserDispatcherTests(IsolatedAsyncioTestCase):

    async def test_page_capacity_is_shared_across_engines(self):
        dispatcher = object.__new__(BrowserSearchDispatcher)
        dispatcher.max_concurrent_pages = 2
        dispatcher.google_max_concurrent_pages = 1
        active = 0
        peak = 0
        google_active = 0
        google_peak = 0

        class FakeManager:
            async def search(self, _request):
                nonlocal active, peak, google_active, google_peak
                active += 1
                peak = max(peak, active)
                if _request.engine == "google":
                    google_active += 1
                    google_peak = max(google_peak, google_active)
                await asyncio.sleep(0.01)
                if _request.engine == "google":
                    google_active -= 1
                active -= 1
                return {"ok": True, "status": "ok", "results": []}

        dispatcher._manager = FakeManager()
        requests = [
            SearchRequest(str(index), engine="google" if index % 2 else "duckduckgo")
            for index in range(12)
        ]
        results = await asyncio.gather(
            *(dispatcher._search(request) for request in requests)
        )

        self.assertEqual(2, peak)
        self.assertEqual(1, google_peak)
        self.assertEqual(12, len(results))


class GoogleBrowserEngineTests(TestCase):

    def test_request_builds_worker_payload(self):
        params = {
            "headers": {},
            "pageno": 2,
            "searxng_locale": "zh-CN",
            "safesearch": 1,
            "time_range": "week",
        }
        google_browser.request("卡莲", params)
        self.assertEqual("POST", params["method"])
        self.assertTrue(params["url"].endswith("/v1/search"))
        self.assertEqual("卡莲", params["json"]["query"])
        self.assertEqual("zh-CN", params["json"]["locale"])
        self.assertEqual("google", params["json"]["engine"])

    def test_response_maps_results(self):
        response = Mock()
        response.json.return_value = {
            "ok": True,
            "results": [
                {"title": "Title", "url": "https://example.test", "content": "Snippet"}
            ],
        }
        results = google_browser.response(response)
        self.assertEqual(1, len(results))
        self.assertEqual("https://example.test", results[0]["url"])


class DuckDuckGoBrowserEngineTests(TestCase):

    def test_request_builds_worker_payload(self):
        params = {
            "headers": {},
            "pageno": 1,
            "searxng_locale": "zh-CN",
            "safesearch": 0,
            "time_range": None,
        }
        duckduckgo_browser.request("卡莲", params)
        self.assertEqual("POST", params["method"])
        self.assertTrue(params["url"].endswith("/v1/search"))
        self.assertEqual("duckduckgo", params["json"]["engine"])
        self.assertEqual("卡莲", params["json"]["query"])

    def test_response_maps_results(self):
        response = Mock()
        response.json.return_value = {
            "ok": True,
            "results": [
                {"title": "Title", "url": "https://example.test", "content": "Snippet"}
            ],
        }
        results = duckduckgo_browser.response(response)
        self.assertEqual(1, len(results))
        self.assertEqual("https://example.test", results[0]["url"])
