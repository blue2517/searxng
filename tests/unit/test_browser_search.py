# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,missing-class-docstring

from unittest import TestCase
from unittest.mock import Mock
from socketserver import ThreadingMixIn

from searx.browser_search.manager import (
    BrowserSearchManager,
    DEFAULT_USER_AGENT,
    SearchRequest,
)
from searx.browser_search.proxy_pool import ProxyEndpoint, ProxyPool
from searx.browser_search.socks_bridge import Socks5AuthBridge
from searx.browser_search.server import BrowserSearchHTTPServer
from searx.engines import google_browser


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

    def test_default_user_agent_matches_host_platform(self):
        self.assertNotIn("HeadlessChrome", DEFAULT_USER_AGENT)

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

    def test_block_reason_detects_javascript_page(self):
        page = Mock()
        page.url = "https://www.google.com/search?q=test"
        page.locator.return_value.inner_text.return_value = (
            "Enable JavaScript to continue"
        )
        self.assertEqual(
            "javascript_required", BrowserSearchManager._block_reason(page)
        )

    def test_search_retries_direct_then_rotates_proxy(self):
        manager = BrowserSearchManager(
            {
                "profile_dir": "unused",
                "max_attempts": 4,
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
                {"ok": True, "status": "ok", "results": []},
            ]
        )
        result = manager.search(SearchRequest("test"))
        self.assertTrue(result["ok"])
        self.assertEqual(4, result["attempts"])
        self.assertEqual(4, manager._perform.call_count)
        routes = [call.args[1].name for call in manager._perform.call_args_list]
        self.assertEqual(
            ["direct", "direct", "socks5://a.test:1080", "socks5://b.test:1080"], routes
        )

    def test_search_clears_route_after_rate_limit(self):
        manager = BrowserSearchManager({"profile_dir": "unused", "max_attempts": 2})
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
        manager._close_route.assert_called()


class BrowserServerTests(TestCase):

    def test_http_server_keeps_playwright_on_one_thread(self):
        self.assertFalse(issubclass(BrowserSearchHTTPServer, ThreadingMixIn))


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
