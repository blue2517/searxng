# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,missing-class-docstring

import json
from pathlib import Path
import tempfile
import threading
import time
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, Mock, patch

import httpx

from searx import server_config, settings
from searx.browser_search.auth_state import (
    clear_route_auth_files,
    get_route_login_status,
    has_google_auth_cookies,
    write_route_auth_meta,
)
from searx.browser_search.manager import BrowserSearchManager, Route
from searx.browser_search.server import BrowserSearchHTTPServer


class GoogleBrowserLoginStateTests(TestCase):

    def test_has_google_auth_cookies_respects_expiry(self):
        future = time.time() + 3600
        past = time.time() - 60
        self.assertTrue(
            has_google_auth_cookies(
                [{"name": "SID", "value": "ok", "domain": ".google.com", "expires": future}]
            )
        )
        self.assertFalse(
            has_google_auth_cookies(
                [{"name": "SID", "value": "old", "domain": ".google.com", "expires": past}]
            )
        )
        self.assertFalse(
            has_google_auth_cookies(
                [{"name": "NID", "value": "anon", "domain": ".google.com", "expires": future}]
            )
        )

    def test_route_login_status_and_clear_removes_legacy_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_path = root / "google-direct" / "storage-state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "cookies": [
                            {
                                "name": "SID",
                                "value": "sidval",
                                "domain": ".google.com",
                                "path": "/",
                                "expires": time.time() + 3600,
                            }
                        ],
                        "origins": [],
                    }
                ),
                encoding="utf-8",
            )
            legacy_file = root / "google-auth-state.json"
            legacy_file.write_text("{}", encoding="utf-8")
            write_route_auth_meta(
                state_path, logged_in=True, reason="browser_login", route="direct"
            )

            status = get_route_login_status(state_path, route_name="direct")
            self.assertTrue(status["has_session"])
            self.assertTrue(status["has_auth_cookies"])
            self.assertIs(status["logged_in"], True)
            self.assertEqual("browser_login", status["reason"])

            clear_route_auth_files(root)
            self.assertFalse(state_path.exists())
            self.assertFalse(legacy_file.exists())
            cleared = get_route_login_status(state_path, route_name="direct")
            self.assertFalse(cleared["has_session"])
            self.assertFalse(cleared["has_auth_cookies"])
            self.assertIsNone(cleared["logged_in"])


class ManagerGoogleLoginTests(IsolatedAsyncioTestCase):

    async def test_logged_out_page_updates_route_auth_meta(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BrowserSearchManager({"profile_dir": tmpdir})
            route = Route("direct", "direct")
            key = manager._context_key(route, "zh-CN", "google")

            fake_page = Mock()
            fake_page.evaluate = AsyncMock(
                return_value={"hasLoginLink": True, "hasAccountUi": False}
            )
            fake_context = Mock()
            fake_context.cookies = AsyncMock(return_value=[])

            await manager._update_google_login_status(
                key,
                route,
                fake_page,
                fake_context,
                [{"title": "t", "url": "https://www.google.com/goto?url=abc"}],
            )

            status = manager.google_login_status()
            self.assertIs(status["logged_in"], False)
            self.assertEqual("session_logged_out", status["reason"])

    async def test_clear_google_session_closes_contexts_and_deletes_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BrowserSearchManager({"profile_dir": tmpdir})
            state_path = manager._state_path("google-direct")
            state_path.write_text('{"cookies": [], "origins": []}', encoding="utf-8")
            fake_ctx = AsyncMock()
            manager._context_lock = AsyncMock()
            manager._context_lock.__aenter__ = AsyncMock(return_value=None)
            manager._context_lock.__aexit__ = AsyncMock(return_value=False)
            manager._contexts["google-direct"] = fake_ctx
            manager._context_active_pages["google-direct"] = 0

            status = await manager.clear_google_session()

            fake_ctx.close.assert_awaited_once()
            self.assertNotIn("google-direct", manager._contexts)
            self.assertFalse(state_path.exists())
            self.assertFalse(status["has_session"])


class ServerConfigGoogleLoginTests(TestCase):

    def test_snapshot_and_clear_google_auth_use_active_route(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_settings = {
                "engines": [],
                "outgoing": {
                    "proxy_pool": {
                        "enabled": True,
                        "entries": ["socks5://proxy.test:1080"],
                    }
                },
                "browser_search": {
                    "enabled": False,
                    "profile_dir": tmpdir,
                },
            }
            with patch.dict(settings, fake_settings, clear=True):
                snap = server_config.snapshot()
                self.assertEqual("socks5://proxy.test:1080", snap["google_auth"]["route"])
                self.assertFalse(snap["google_auth"]["has_session"])

                state_file = Path(snap["google_auth"]["state_file"])
                state_file.parent.mkdir(parents=True, exist_ok=True)
                state_file.write_text(
                    json.dumps(
                        {
                            "cookies": [
                                {
                                    "name": "SID",
                                    "value": "s",
                                    "domain": ".google.com",
                                    "expires": time.time() + 3600,
                                }
                            ],
                            "origins": [],
                        }
                    ),
                    encoding="utf-8",
                )
                snap2 = server_config.snapshot()
                self.assertTrue(snap2["google_auth"]["has_auth_cookies"])

                cleared = server_config.clear_google_auth()
                self.assertFalse(cleared["has_session"])
                self.assertFalse(state_file.exists())


class WorkerAuthEndpointTests(TestCase):

    def test_auth_and_config_reload_endpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_manager = Mock()
            fake_manager.config = {"profile_dir": tmpdir}
            fake_manager.google_login_status.return_value = {
                "route": "direct",
                "has_session": False,
                "has_auth_cookies": False,
                "logged_in": None,
            }
            fake_manager.clear_google_session.return_value = {
                "route": "direct",
                "has_session": False,
                "has_auth_cookies": False,
                "logged_in": None,
            }
            fake_manager.reload_proxy_config.return_value = {
                "ok": True,
                "route": "socks5://proxy.test:1080",
                "proxy_enabled": True,
            }
            server = BrowserSearchHTTPServer(("127.0.0.1", 0), fake_manager)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{port}"
                initial = httpx.get(f"{base}/v1/auth/google", timeout=5.0)
                self.assertEqual(200, initial.status_code)
                self.assertEqual("direct", initial.json()["route"])

                rejected = httpx.post(
                    f"{base}/v1/auth/google",
                    json={"raw": "SID=abc"},
                    timeout=5.0,
                )
                self.assertEqual(400, rejected.status_code)

                cleared = httpx.post(
                    f"{base}/v1/auth/google",
                    json={"action": "clear"},
                    timeout=5.0,
                )
                self.assertEqual(200, cleared.status_code)
                fake_manager.clear_google_session.assert_called_once()

                reloaded = httpx.post(
                    f"{base}/v1/config/reload",
                    json={
                        "proxy_pool": {
                            "enabled": True,
                            "entries": ["socks5://proxy.test:1080"],
                        }
                    },
                    timeout=5.0,
                )
                self.assertEqual(200, reloaded.status_code)
                self.assertTrue(reloaded.json()["proxy_enabled"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
