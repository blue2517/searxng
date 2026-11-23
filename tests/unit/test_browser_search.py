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

    def test_parse_proxy_supports_socks5h(self):
        proxy = ProxyEndpoint.parse(0, "socks5h://example.test:1080")
        self.assertEqual("socks5", proxy.scheme)
        self.assertEqual("socks5://example.test:1080", proxy.display_name)

    def test_primary_proxy_is_fixed_without_rotation(self):
        pool = ProxyPool(
            ["socks5://a.test:1", "socks5://b.test:2", "socks5://c.test:3"]
        )
        self.assertEqual("a.test", pool.primary.host)
        self.assertEqual(["a.test"], [item.host for item in pool.round()])
        self.assertEqual(["a.test"], [item.host for item in pool.round()])


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
        self.assertIn("gl=hk", url)
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

    async def test_create_context_loads_existing_route_state_directly(self):
        manager = BrowserSearchManager({"profile_dir": "unused"})
        manager.profile_root = Path(tempfile.mkdtemp())
        manager._browser = Mock()
        manager._browser.new_context = AsyncMock(return_value=Mock())
        manager._browser.new_context.return_value.add_init_script = AsyncMock()
        route = Route("direct", "direct")
        key = manager._context_key(route, "en-US")
        state_path = manager._state_path(key)
        state_path.write_text('{"cookies": [], "origins": []}', encoding="utf-8")

        await manager._create_context(route, "en-US", key)

        kwargs = manager._browser.new_context.await_args.kwargs
        self.assertEqual(str(state_path), kwargs["storage_state"])

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

    async def test_search_uses_direct_once_when_proxy_disabled(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "proxy_pool": {
                    "enabled": False,
                    "entries": ["socks5://a.test:1080"],
                },
            }
        )
        manager.start = AsyncMock()
        manager._perform = AsyncMock(
            return_value={"ok": False, "status": "blocked", "reason": "captcha"}
        )

        result = await manager.search(SearchRequest("test"))

        self.assertFalse(result["ok"])
        self.assertEqual(1, result["attempts"])
        self.assertEqual(1, result["routes_tried"])
        self.assertEqual(0, result["recoveries"])
        manager._perform.assert_awaited_once()
        self.assertEqual("direct", manager._perform.await_args.args[1].name)

    async def test_search_uses_configured_proxy_once_when_enabled(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "proxy_pool": {
                    "enabled": True,
                    "entries": ["socks5://a.test:1080", "socks5://b.test:1080"],
                },
            }
        )
        manager.start = AsyncMock()
        manager._perform = AsyncMock(
            return_value={"ok": False, "status": "blocked", "reason": "captcha"}
        )

        result = await manager.search(SearchRequest("test"))

        self.assertFalse(result["ok"])
        self.assertEqual(1, result["attempts"])
        self.assertEqual(1, result["routes_tried"])
        self.assertEqual(0, result["recoveries"])
        manager._perform.assert_awaited_once()
        self.assertEqual("socks5://a.test:1080", manager._perform.await_args.args[1].name)

    async def test_warm_uses_active_route(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "proxy_pool": {
                    "enabled": True,
                    "entries": ["socks5://a.test:1080"],
                },
            }
        )
        manager.start = AsyncMock()
        manager._context = AsyncMock(return_value=("google-proxy", Mock()))

        await manager.warm("zh-CN")

        self.assertEqual("socks5://a.test:1080", manager._context.await_args.args[0].name)

    async def test_reload_proxy_config_switches_route_and_closes_old_contexts(self):
        manager = BrowserSearchManager({"profile_dir": "unused"})
        manager._context_lock = asyncio.Lock()
        fake_ctx = AsyncMock()
        manager._contexts["google-direct"] = fake_ctx
        manager._context_active_pages["google-direct"] = 0

        res = await manager.reload_proxy_config(
            {"enabled": True, "entries": ["socks5://a.test:1080"]}
        )

        self.assertTrue(res["proxy_enabled"])
        self.assertEqual("socks5://a.test:1080", res["route"])
        fake_ctx.close.assert_awaited_once()
        self.assertEqual("socks5://a.test:1080", manager._active_route().name)


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
