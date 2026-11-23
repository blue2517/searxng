# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,missing-class-docstring

import asyncio
import base64
import json
from pathlib import Path
import tempfile
import threading
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, Mock, patch

import httpx

from searx import settings, webapp
from searx.browser_search.manager import BrowserSearchManager, Route, SearchRequest
from searx.browser_search.server import BrowserSearchHTTPServer
from searx.engines import duckduckgo_browser, google_browser
from searx.exceptions import SearxEngineCaptchaException


class BrowserEngineCaptchaMappingTests(TestCase):

    def test_request_disables_raise_for_httperror(self):
        for mod in (google_browser, duckduckgo_browser):
            params = {
                "headers": {},
                "pageno": 1,
                "searxng_locale": "zh-CN",
                "safesearch": 0,
                "time_range": None,
            }
            mod.request("test", params)
            self.assertFalse(params["raise_for_httperror"])

    def test_blocked_challenge_raises_captcha_exception(self):
        for reason in (
            "google_challenge_url",
            "unusual_traffic",
            "captcha",
            "consent_required",
            "verification_in_progress",
        ):
            resp = Mock()
            resp.status_code = 502
            resp.json.return_value = {
                "ok": False,
                "status": "blocked",
                "reason": reason,
            }
            with self.assertRaises(SearxEngineCaptchaException):
                google_browser.response(resp)


class ManagerVerificationTests(IsolatedAsyncioTestCase):

    async def test_verify_lifecycle_auto_solves_and_persists_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BrowserSearchManager({"profile_dir": tmpdir})
            manager._browser = object()
            manager._start_lock = asyncio.Lock()
            manager._context_lock = asyncio.Lock()

            page = AsyncMock()
            page.url = "https://www.google.com/sorry/index?continue=https://www.google.com/search?q=zero"
            page.title = AsyncMock(return_value="Sorry...")
            page.is_closed = Mock(return_value=False)
            page.screenshot = AsyncMock(return_value=b"\xff\xd8\xff\xd9")
            page.goto = AsyncMock()
            page.mouse = AsyncMock()
            page.keyboard = AsyncMock()

            context = AsyncMock()
            context.new_page = AsyncMock(return_value=page)
            context.cookies = AsyncMock(
                return_value=[{"name": "GOOGLE_ABUSE_EXEMPTION", "value": "exempt1"}]
            )

            async def write_storage_state(path=None):
                payload = {
                    "cookies": [
                        {
                            "name": "GOOGLE_ABUSE_EXEMPTION",
                            "value": "exempt1",
                            "domain": ".google.com",
                            "path": "/",
                        }
                    ],
                    "origins": [],
                }
                if path:
                    Path(path).write_text(json.dumps(payload), encoding="utf-8")
                return payload

            context.storage_state = AsyncMock(side_effect=write_storage_state)
            manager._contexts["google-direct"] = context
            manager._last_challenges["google"] = {
                "engine": "google",
                "route": "direct",
                "profile_key": "direct",
                "locale": "zh-CN",
                "query": "zero",
                "search_url": "https://www.google.com/search?q=zero&gl=hk&hl=zh-CN",
                "challenge_url": page.url,
                "reason": "google_challenge_url",
                "occurred_at": 1.0,
                "solved": False,
            }

            with (
                patch.object(
                    BrowserSearchManager,
                    "_block_reason",
                    new=AsyncMock(side_effect=["google_challenge_url", None]),
                ),
                patch.object(
                    BrowserSearchManager,
                    "_wait_for_results",
                    new=AsyncMock(return_value=True),
                ),
            ):
                started = await manager.verify_start(engine="google")
                self.assertTrue(started["active"])
                self.assertFalse(started["solved"])

                blocked = await manager._perform(
                    SearchRequest("zero", engine="google", locale="zh-CN"),
                    Route("direct", "direct"),
                )
                self.assertEqual("verification_in_progress", blocked["reason"])

                frame, frame_status = await manager.verify_frame(engine="google", force=True)
                self.assertEqual(b"\xff\xd8\xff\xd9", frame)
                self.assertTrue(frame_status["active"])

                page.url = "https://www.google.com/search?q=zero&gl=hk&hl=zh-CN"
                after_click = await manager.verify_input(
                    {"engine": "google", "kind": "click", "x": 100, "y": 200}
                )
                page.mouse.click.assert_awaited_once_with(
                    100, 200, button="left", click_count=1
                )
                self.assertTrue(after_click["solved"])
                self.assertTrue((Path(tmpdir) / "google-direct" / "storage-state.json").exists())

                done = await manager.verify_complete(engine="google", close_session=True)
                self.assertFalse(done["active"])
                self.assertTrue(done["solved"])
                page.close.assert_awaited_once()

    async def test_verify_input_rejects_disallowed_goto_url(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BrowserSearchManager({"profile_dir": tmpdir})
            page = AsyncMock()
            page.is_closed = Mock(return_value=False)
            manager._verify_session = {
                "session_id": "abc",
                "engine": "google",
                "route": Route("direct", "direct"),
                "locale": "zh-CN",
                "context_key": "google-direct",
                "context": AsyncMock(),
                "page": page,
                "target_url": "https://www.google.com/search?q=test",
                "current_url": "https://www.google.com/sorry/index",
                "title": "",
                "reason": "google_challenge_url",
                "solved": False,
                "started_at": 0.0,
                "last_activity_at": 1e12,
                "last_frame": None,
                "last_frame_at": 0.0,
            }
            res = await manager.verify_input(
                {"engine": "google", "kind": "goto", "url": "http://127.0.0.1:8080/"}
            )
            self.assertFalse(res["ok"])
            self.assertEqual("disallowed verification URL", res["reason"])

    async def test_login_mode_opens_google_signin_and_persists_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BrowserSearchManager({"profile_dir": tmpdir})
            manager._browser = object()
            manager._start_lock = asyncio.Lock()
            manager._context_lock = asyncio.Lock()

            page = AsyncMock()
            page.url = "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fwww.google.com%2F&hl=zh-CN"
            page.title = AsyncMock(return_value="Sign in - Google Accounts")
            page.is_closed = Mock(return_value=False)
            page.goto = AsyncMock()
            page.mouse = AsyncMock()
            page.keyboard = AsyncMock()
            page.evaluate = AsyncMock(
                return_value={"hasLoginLink": False, "hasAccountUi": True}
            )

            context = AsyncMock()
            context.new_page = AsyncMock(return_value=page)
            context.cookies = AsyncMock(
                return_value=[{"name": "SID", "value": "sid123", "domain": ".google.com"}]
            )

            async def write_storage_state(path=None):
                payload = {
                    "cookies": [
                        {
                            "name": "SID",
                            "value": "sid123",
                            "domain": ".google.com",
                            "path": "/",
                        }
                    ],
                    "origins": [],
                }
                if path:
                    Path(path).write_text(json.dumps(payload), encoding="utf-8")
                return payload

            context.storage_state = AsyncMock(side_effect=write_storage_state)
            manager._contexts["google-direct"] = context

            with patch.object(
                BrowserSearchManager,
                "_block_reason",
                new=AsyncMock(return_value=None),
            ):
                started = await manager.verify_start(engine="google", mode="login")
                self.assertTrue(started["active"])
                self.assertEqual("login", started["mode"])
                self.assertFalse(started["solved"])
                self.assertIn("accounts.google.com/ServiceLogin", page.goto.await_args.args[0])

                page.url = "https://www.google.com/"
                after_login = await manager.verify_status(engine="google")
                self.assertTrue(after_login["solved"])
                login_status = manager.google_login_status()
                self.assertIs(login_status["logged_in"], True)
                self.assertTrue(login_status["has_auth_cookies"])
                await manager.verify_close()


class WorkerVerifyEndpointTests(TestCase):

    def test_verify_endpoints_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_manager = Mock()
            fake_manager.config = {"profile_dir": tmpdir}
            fake_manager.verify_status.return_value = {
                "ok": True,
                "active": False,
                "engine": "google",
                "solved": False,
            }
            fake_manager.verify_start.return_value = {
                "ok": True,
                "active": True,
                "engine": "google",
                "solved": False,
            }
            fake_manager.verify_frame.return_value = (
                b"\xff\xd8\xff\xd9",
                {"solved": False, "reason": "google_challenge_url"},
            )
            fake_manager.verify_input.return_value = {
                "ok": True,
                "active": True,
                "engine": "google",
                "solved": True,
            }
            fake_manager.verify_complete.return_value = {
                "ok": True,
                "active": False,
                "engine": "google",
                "solved": True,
            }
            fake_manager.verify_close.return_value = {
                "ok": True,
                "active": False,
                "engine": "google",
                "solved": False,
            }
            server = BrowserSearchHTTPServer(("127.0.0.1", 0), fake_manager)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{port}"
                self.assertEqual(200, httpx.get(f"{base}/v1/verify/status?engine=google").status_code)
                self.assertTrue(
                    httpx.post(f"{base}/v1/verify/start", json={"engine": "google"}).json()["active"]
                )
                frame = httpx.get(f"{base}/v1/verify/frame?engine=google&force=1")
                self.assertEqual(200, frame.status_code)
                self.assertEqual("image/jpeg", frame.headers["content-type"])
                self.assertEqual(b"\xff\xd8\xff\xd9", frame.content)

                inp = httpx.post(
                    f"{base}/v1/verify/input",
                    json={"engine": "google", "kind": "click", "x": 10, "y": 20},
                )
                self.assertTrue(inp.json()["solved"])
                self.assertFalse(
                    httpx.post(f"{base}/v1/verify/complete", json={"engine": "google"}).json()["active"]
                )
                self.assertEqual(200, httpx.post(f"{base}/v1/verify/close", json={}).status_code)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


class WebappVerifyRouteTests(TestCase):

    def test_browser_verify_routes_require_auth_and_resume_engine(self):
        fake_proc = Mock()
        fake_proc.suspended_status = Mock()
        fake_auth = base64.b64encode(b"admin:secret").decode("ascii")
        headers = {"Authorization": f"Basic {fake_auth}"}
        with (
            patch.dict(
                settings["server"],
                {"auth_username": "admin", "auth_password": "secret"},
                clear=False,
            ),
            patch.dict(
                settings,
                {"browser_search": {"enabled": True, "endpoint": "http://127.0.0.1:8890"}},
                clear=False,
            ),
            patch.dict(webapp.PROCESSORS, {"google browser": fake_proc}, clear=False),
        ):
            client = webapp.app.test_client()
            unauth = client.get("/browser-verify")
            self.assertEqual(401, unauth.status_code)

            page = client.get("/browser-verify?engine=google&q=test", headers=headers)
            self.assertEqual(200, page.status_code)
            self.assertIn("网页人机验证", page.get_data(as_text=True))

            login_page = client.get("/browser-verify?engine=google&mode=login", headers=headers)
            self.assertEqual(200, login_page.status_code)
            self.assertIn("Google 账号登录", login_page.get_data(as_text=True))

            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = json.dumps({"ok": True, "solved": True}).encode("utf-8")
            with patch.object(webapp.httpx, "request", return_value=mock_resp):
                done = client.post(
                    "/browser-verify/complete",
                    json={"engine": "google"},
                    headers=headers,
                )
                self.assertEqual(200, done.status_code)
                fake_proc.suspended_status.resume.assert_called_once()
