# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,missing-class-docstring

from unittest import TestCase
from unittest.mock import Mock
from socketserver import ThreadingMixIn
from tempfile import TemporaryDirectory

from searx.browser_search.manager import (
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


class BrowserManagerTests(TestCase):

    def test_default_user_agent_is_detected_from_current_browser(self):
        manager = BrowserSearchManager({})
        self.assertIsNone(manager.user_agent)
        browser = Mock()
        page = browser.new_page.return_value
        page.evaluate.return_value = (
            "Mozilla/5.0 HeadlessChrome/151.0.0.0 Safari/537.36"
        )
        manager._playwright = Mock()
        manager._playwright.chromium.launch.return_value = browser

        self.assertEqual(
            "Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36",
            manager._effective_user_agent(),
        )
        self.assertEqual(
            "Mozilla/5.0 Chrome/151.0.0.0 Safari/537.36",
            manager._effective_user_agent(),
        )
        manager._playwright.chromium.launch.assert_called_once()
        browser.close.assert_called_once_with()

    def test_headful_mode_keeps_browser_native_user_agent(self):
        manager = BrowserSearchManager({"headless": False})
        manager._playwright = Mock()
        self.assertIsNone(manager._effective_user_agent())
        manager._playwright.chromium.launch.assert_not_called()

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
        self.assertEqual("en-US", BrowserSearchManager._normalize_locale("all"))

    def test_launch_context_uses_request_locale_and_native_user_agent(self):
        with TemporaryDirectory() as profile_dir:
            manager = BrowserSearchManager(
                {"profile_dir": profile_dir, "browser_channel": ""}
            )
            context = Mock()
            manager._playwright = Mock()
            manager._playwright.chromium.launch_persistent_context.return_value = (
                context
            )
            manager._resolved_user_agent = "detected-agent"
            manager._user_agent_checked = True

            self.assertIs(context, manager._context(Route("direct", "direct"), "zh-CN"))

            kwargs = (
                manager._playwright.chromium.launch_persistent_context.call_args.kwargs
            )
            self.assertEqual("zh-CN", kwargs["locale"])
            self.assertEqual("detected-agent", kwargs["user_agent"])
            context.add_init_script.assert_not_called()

    def test_locale_change_restarts_context_without_clearing_cookies(self):
        manager = BrowserSearchManager({"profile_dir": "unused"})
        route = Route("direct", "direct")
        old_context = Mock()
        new_context = Mock()
        manager._contexts[route.profile_key] = old_context
        manager._context_locales[route.profile_key] = "en-US"
        manager._launch_context = Mock(return_value=new_context)

        self.assertIs(new_context, manager._context(route, "zh-CN"))

        old_context.clear_cookies.assert_not_called()
        old_context.close.assert_called_once_with()
        manager._launch_context.assert_called_once_with(route, "zh-CN")

    def test_block_reason_detects_javascript_page(self):
        page = Mock()
        page.url = "https://www.google.com/search?q=test"
        page.locator.return_value.inner_text.return_value = (
            "Enable JavaScript to continue"
        )
        self.assertEqual(
            "javascript_required", BrowserSearchManager._block_reason(page)
        )

    def test_block_reason_detects_localized_challenge_and_captcha_dom(self):
        page = Mock()
        page.url = "https://www.google.com/search?q=test"
        page.locator.return_value.inner_text.return_value = "检测到异常流量"
        self.assertEqual("unusual_traffic", BrowserSearchManager._block_reason(page))

        page.locator.return_value.inner_text.return_value = ""
        page.locator.return_value.count.return_value = 1
        self.assertEqual("captcha", BrowserSearchManager._block_reason(page))

    def test_duckduckgo_block_reason_detects_bot_challenge(self):
        page = Mock()
        page.url = "https://duckduckgo.com/?q=test"
        page.locator.return_value.inner_text.return_value = (
            "Unfortunately, bots use DuckDuckGo too."
        )
        self.assertEqual(
            "captcha", BrowserSearchManager._block_reason(page, "duckduckgo")
        )

    def test_duckduckgo_extractor_uses_rendered_page(self):
        page = Mock()
        page.evaluate.return_value = [
            {"title": "Title", "url": "https://example.test", "content": "Snippet"}
        ]
        results = BrowserSearchManager._extract_results(
            page, engine="duckduckgo"
        )
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

    def test_search_retries_challenge_on_same_route_before_cleanup(self):
        manager = BrowserSearchManager(
            {"profile_dir": "unused", "max_attempts": 3, "challenge_retry_delay": 0}
        )
        manager.start = Mock()
        manager._close_route = Mock()
        manager._perform = Mock(
            side_effect=[
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": True, "status": "ok", "results": []},
            ]
        )

        result = manager.search(SearchRequest("test"))

        self.assertTrue(result["ok"])
        self.assertEqual(2, result["attempts"])
        self.assertEqual(2, manager._perform.call_count)
        self.assertEqual(
            [call.args[1].name for call in manager._perform.call_args_list],
            ["direct", "direct"],
        )
        manager._close_route.assert_not_called()

    def test_search_retries_direct_then_rotates_proxy(self):
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
        manager.start = Mock()
        manager._close_route = Mock()
        manager._perform = Mock(
            side_effect=[
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": False, "status": "blocked", "reason": "captcha"},
                {"ok": True, "status": "ok", "results": []},
            ]
        )
        result = manager.search(SearchRequest("test"))
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
        closed_routes = [
            call.args[0].name for call in manager._close_route.call_args_list
        ]
        self.assertEqual(["direct", "socks5://a.test:1080"], closed_routes)
        self.assertTrue(
            all(
                call.kwargs.get("clear_cookies")
                for call in manager._close_route.call_args_list
            )
        )

    def test_search_clears_route_after_rate_limit(self):
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
        manager.start = Mock()
        manager._close_route = Mock()
        manager._perform = Mock(
            side_effect=[
                {"ok": False, "status": "rate_limited", "reason": "http_429"},
                {"ok": True, "status": "ok", "results": []},
            ]
        )
        result = manager.search(SearchRequest("test"))
        self.assertTrue(result["ok"])
        self.assertEqual(2, result["attempts"])
        manager._close_route.assert_called_once_with(
            Route("direct", "google-direct"), clear_cookies=False
        )

    def test_browser_configuration_failure_does_not_rotate_proxy(self):
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
        manager.start = Mock()
        manager._close_route = Mock()
        manager._perform = Mock(
            return_value={
                "ok": False,
                "status": "blocked",
                "reason": "browser_update_required",
            }
        )

        result = manager.search(SearchRequest("test"))

        self.assertFalse(result["ok"])
        self.assertEqual(1, result["attempts"])
        manager._perform.assert_called_once()
        manager._close_route.assert_called_once_with(
            Route("direct", "google-direct"), clear_cookies=False
        )

    def test_transport_error_rotates_without_clearing_cookies(self):
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
        manager.start = Mock()
        manager._close_route = Mock()
        manager._perform = Mock(
            side_effect=[
                {
                    "ok": False,
                    "status": "route_error",
                    "reason": "transport_error",
                },
                {"ok": True, "status": "ok", "results": []},
            ]
        )

        result = manager.search(SearchRequest("test"))

        self.assertTrue(result["ok"])
        self.assertEqual(2, result["attempts"])
        self.assertEqual(
            [call.args[1].name for call in manager._perform.call_args_list],
            ["direct", "socks5://a.test:1080"],
        )
        manager._close_route.assert_called_once_with(
            Route("direct", "google-direct"), clear_cookies=False
        )


class BrowserServerTests(TestCase):

    def test_http_server_accepts_parallel_lane_requests(self):
        self.assertTrue(issubclass(BrowserSearchHTTPServer, ThreadingMixIn))


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
