# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,missing-class-docstring

import json
import os
from pathlib import Path
import tempfile
import threading
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, Mock, patch

import httpx

from searx import server_config, settings
from searx.browser_search.auth_state import (
    clear_google_auth_state,
    get_google_auth_status,
    merge_storage_states,
    parse_google_cookies_input,
    save_google_auth_state,
)
from searx.browser_search.manager import BrowserSearchManager, Route
from searx.browser_search.server import BrowserSearchHTTPServer


SAMPLE_HEADER = (
    "HSID=abc1; SSID=abc2; APISID=a/b; SAPISID=c/d; "
    "S=billing-ui-v3=foo:bar=baz; "
    "SID=sidval; __Secure-1PSID=psid1; __Secure-3PSID=psid3; "
    "__Secure-1PSIDTS=ts1; NID=nidval"
)


class AuthStateParserTests(TestCase):

    def test_parses_cookie_header_with_equals_in_value(self):
        state, fmt = parse_google_cookies_input(f"Cookie: {SAMPLE_HEADER}")
        self.assertEqual("cookie_header", fmt)
        by_name = {c["name"]: c for c in state["cookies"]}
        self.assertEqual("billing-ui-v3=foo:bar=baz", by_name["S"]["value"])
        self.assertTrue(by_name["__Secure-3PSID"]["secure"])
        self.assertEqual("None", by_name["__Secure-3PSID"]["sameSite"])
        self.assertTrue(by_name["SID"]["httpOnly"])
        self.assertEqual(".google.com", by_name["SID"]["domain"])
        self.assertGreater(by_name["SID"]["expires"], 0)

    def test_parses_cookie_editor_json_array(self):
        payload = json.dumps(
            [
                {
                    "name": "SID",
                    "value": "s1",
                    "domain": ".google.com",
                    "path": "/",
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "no_restriction",
                    "expirationDate": 1893456000,
                },
                {
                    "name": "unrelated",
                    "value": "dropme",
                    "domain": ".example.com",
                    "path": "/",
                },
            ]
        )
        state, fmt = parse_google_cookies_input(payload)
        self.assertEqual("cookie_json", fmt)
        self.assertEqual(1, len(state["cookies"]))
        self.assertEqual("None", state["cookies"][0]["sameSite"])
        self.assertEqual(1893456000, state["cookies"][0]["expires"])

    def test_parses_netscape_cookies_txt(self):
        netscape = (
            "# Netscape HTTP Cookie File\n"
            "#HttpOnly_.google.com\tTRUE\t/\tTRUE\t1893456000\t__Secure-1PSID\tval1\n"
            ".google.com\tTRUE\t/\tFALSE\t1893456000\tPREF\ttz=UTC\n"
        )
        state, fmt = parse_google_cookies_input(netscape)
        self.assertEqual("netscape", fmt)
        by_name = {c["name"]: c for c in state["cookies"]}
        self.assertTrue(by_name["__Secure-1PSID"]["httpOnly"])
        self.assertTrue(by_name["__Secure-1PSID"]["secure"])
        self.assertEqual("tz=UTC", by_name["PREF"]["value"])

    def test_rejects_missing_core_google_auth_cookies(self):
        with self.assertRaises(ValueError):
            parse_google_cookies_input("PREF=tz=UTC; NID=only_nid")

    def test_merge_storage_states_prefers_override_cookies(self):
        base = {
            "cookies": [
                {"name": "SID", "value": "old", "domain": ".google.com", "path": "/"},
                {"name": "SOCS", "value": "keep", "domain": ".google.com", "path": "/"},
            ],
            "origins": [],
        }
        override = {
            "cookies": [
                {"name": "SID", "value": "new", "domain": ".google.com", "path": "/"},
            ],
            "origins": [],
        }
        merged = merge_storage_states(base, override)
        by_name = {c["name"]: c["value"] for c in merged["cookies"]}
        self.assertEqual("new", by_name["SID"])
        self.assertEqual("keep", by_name["SOCS"])


class ManagerGoogleAuthTests(IsolatedAsyncioTestCase):

    async def test_force_clean_context_still_keeps_imported_google_auth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_path = Path(tmpdir) / "google-auth-state.json"
            state, fmt = parse_google_cookies_input(SAMPLE_HEADER)
            save_google_auth_state(auth_path, state, source_format=fmt)

            manager = BrowserSearchManager(
                {
                    "profile_dir": tmpdir,
                    "google_auth_state_file": str(auth_path),
                }
            )
            fake_context = Mock()
            fake_context.add_init_script = AsyncMock()
            fake_context.storage_state = AsyncMock(return_value=state)
            fake_browser = Mock()
            fake_browser.new_context = AsyncMock(return_value=fake_context)
            manager._browser = fake_browser

            route = Route("direct", "direct")
            key = manager._context_key(route, "zh-CN", "google")
            route_state_file = manager._state_path(key)
            route_state_file.write_text(
                json.dumps(
                    {
                        "cookies": [
                            {
                                "name": "SID",
                                "value": "stale",
                                "domain": ".google.com",
                                "path": "/",
                            },
                            {
                                "name": "STALE_CHALLENGE",
                                "value": "bad",
                                "domain": ".google.com",
                                "path": "/",
                            },
                        ],
                        "origins": [],
                    }
                ),
                encoding="utf-8",
            )
            manager._force_clean_context.add(key)

            await manager._create_context(route, "zh-CN", key)

            kwargs = fake_browser.new_context.call_args.kwargs
            passed_cookies = {
                c["name"]: c["value"] for c in kwargs["storage_state"]["cookies"]
            }
            self.assertEqual("sidval", passed_cookies["SID"])
            self.assertNotIn("STALE_CHALLENGE", passed_cookies)

    async def test_logged_out_page_does_not_overwrite_saved_google_auth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_path = Path(tmpdir) / "google-auth-state.json"
            state, fmt = parse_google_cookies_input(SAMPLE_HEADER)
            save_google_auth_state(auth_path, state, source_format=fmt)

            manager = BrowserSearchManager(
                {
                    "profile_dir": tmpdir,
                    "google_auth_state_file": str(auth_path),
                    "persist_google_auth": True,
                }
            )
            fake_page = Mock()
            fake_page.evaluate = AsyncMock(
                return_value={"hasLoginLink": True, "hasAccountUi": False}
            )
            fake_context = Mock()
            fake_context.cookies = AsyncMock(return_value=[])
            fake_context.storage_state = AsyncMock(
                return_value={"cookies": [], "origins": []}
            )

            await manager._update_google_auth_after_search(
                fake_page,
                fake_context,
                [{"title": "t", "url": "https://www.google.com/goto?url=abc"}],
            )

            status = get_google_auth_status(auth_path)
            self.assertTrue(status["configured"])
            self.assertIs(status["last_auth_ok"], False)
            self.assertEqual("session_logged_out", status["last_reason"])


class ServerConfigGoogleAuthTests(TestCase):

    def test_import_and_clear_google_auth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_settings = {
                "engines": [],
                "outgoing": {"proxy_pool": {}},
                "browser_search": {
                    "enabled": False,
                    "profile_dir": tmpdir,
                    "google_auth_state_file": "",
                },
            }
            with patch.dict(settings, fake_settings, clear=True):
                status = server_config.import_google_auth(SAMPLE_HEADER)
                self.assertTrue(status["configured"])
                self.assertGreaterEqual(status["cookie_count"], 8)
                snap = server_config.snapshot()
                self.assertTrue(snap["google_auth"]["configured"])

                cleared = server_config.clear_google_auth()
                self.assertFalse(cleared["configured"])
                self.assertFalse((Path(tmpdir) / "google-auth-state.json").exists())
                clear_google_auth_state(Path(tmpdir) / "google-auth-state.json")


class WorkerAuthEndpointTests(TestCase):

    def test_get_post_google_auth_endpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_manager = Mock()
            fake_manager.config = {"profile_dir": tmpdir}
            fake_manager.reload_google_auth = Mock(
                side_effect=lambda **kwargs: get_google_auth_status(
                    Path(tmpdir) / "google-auth-state.json"
                )
            )
            server = BrowserSearchHTTPServer(("127.0.0.1", 0), fake_manager)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{port}"
                initial = httpx.get(f"{base}/v1/auth/google", timeout=5.0)
                self.assertEqual(200, initial.status_code)
                self.assertFalse(initial.json()["configured"])

                bad = httpx.post(
                    f"{base}/v1/auth/google",
                    json={"raw": "PREF=1"},
                    timeout=5.0,
                )
                self.assertEqual(400, bad.status_code)

                imported = httpx.post(
                    f"{base}/v1/auth/google",
                    json={"raw": SAMPLE_HEADER},
                    timeout=5.0,
                )
                self.assertEqual(200, imported.status_code)
                self.assertTrue(imported.json()["configured"])
                self.assertGreaterEqual(imported.json()["cookie_count"], 8)

                cleared = httpx.post(
                    f"{base}/v1/auth/google",
                    json={"action": "clear"},
                    timeout=5.0,
                )
                self.assertEqual(200, cleared.status_code)
                self.assertFalse(cleared.json()["configured"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
