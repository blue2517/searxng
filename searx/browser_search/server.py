# SPDX-License-Identifier: AGPL-3.0-or-later
"""Small loopback HTTP service for the browser-backed SearXNG engine."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import signal
import threading
from typing import Any
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlsplit

from .auth_state import (
    clear_google_auth_state,
    get_google_auth_status,
    parse_google_cookies_input,
    resolve_google_auth_path,
    save_google_auth_state,
)
from .manager import BrowserSearchDispatcher, SearchRequest

logger = logging.getLogger(__name__)


def _config() -> dict[str, Any]:
    from searx import get_setting

    config = dict(get_setting("browser_search", {}))
    bp = config.get("proxy_pool") or {}
    if not bp.get("entries"):
        outgoing_pp = get_setting("outgoing.proxy_pool", {}) or {}
        if outgoing_pp.get("entries"):
            config["proxy_pool"] = {
                "enabled": bool(outgoing_pp.get("enabled", False)),
                "entries": list(outgoing_pp.get("entries", [])),
                "max_attempts": outgoing_pp.get("max_attempts", 3),
            }
    return config


class BrowserSearchHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], manager: BrowserSearchDispatcher):
        super().__init__(address, BrowserSearchHandler)
        self.manager = manager


class BrowserSearchHandler(BaseHTTPRequestHandler):
    server: BrowserSearchHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("browser-search %s", format % args)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", body)

    def _send_bytes(
        self,
        status: int,
        content_type: str,
        body: bytes,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self, max_bytes: int = 64 * 1024) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > max_bytes:
            raise ValueError("invalid request body size")
        if length == 0:
            return {}
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        if path == "/health":
            self._send(200, {"ok": True, "service": "browser-search"})
            return
        if path == "/v1/auth/google":
            auth_path = resolve_google_auth_path(self.server.manager.config)
            self._send(200, {"ok": True, **get_google_auth_status(auth_path)})
            return
        if path == "/v1/verify/status":
            engine = (params.get("engine") or ["google"])[0]
            try:
                status = self.server.manager.verify_status(engine)
                self._send(200 if status.get("ok") else 400, status)
            except Exception as exc:  # pragma: no cover - service boundary
                logger.exception("browser verify status failed")
                self._send(500, {"ok": False, "status": "error", "reason": str(exc)})
            return
        if path == "/v1/verify/frame":
            engine = (params.get("engine") or ["google"])[0]
            force = (params.get("force") or ["0"])[0] in {"1", "true", "yes"}
            try:
                frame, status = self.server.manager.verify_frame(
                    engine=engine, force=force
                )
                self._send_bytes(
                    200,
                    "image/jpeg",
                    frame,
                    headers={
                        "Cache-Control": "no-store",
                        "X-Verify-Solved": "1" if status.get("solved") else "0",
                        "X-Verify-Reason": str(status.get("reason", "")),
                    },
                )
            except ValueError as exc:
                self._send(409, {"ok": False, "status": "no_session", "reason": str(exc)})
            except Exception as exc:  # pragma: no cover - service boundary
                logger.exception("browser verify frame failed")
                self._send(500, {"ok": False, "status": "error", "reason": str(exc)})
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/v1/auth/google":
            try:
                payload = self._read_json_body(max_bytes=512 * 1024)
                if not payload:
                    raise ValueError("invalid request body size")
                auth_path = resolve_google_auth_path(self.server.manager.config)
                action = str(payload.get("action", "import")).strip().lower()
                if action == "clear":
                    clear_google_auth_state(auth_path)
                    status = self.server.manager.reload_google_auth(
                        clear_route_states=True
                    )
                    self._send(200, {"ok": True, **status})
                    return
                if action == "reload":
                    status = self.server.manager.reload_google_auth(
                        clear_route_states=bool(payload.get("clear_route_states", False))
                    )
                    self._send(200, {"ok": True, **status})
                    return
                raw = str(payload.get("raw", ""))
                state, source_format = parse_google_cookies_input(
                    raw, require_auth_cookies=True
                )
                save_google_auth_state(auth_path, state, source_format=source_format)
                status = self.server.manager.reload_google_auth(
                    clear_route_states=False
                )
                self._send(200, {"ok": True, **status})
                return
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send(
                    400, {"ok": False, "status": "invalid_request", "reason": str(exc)}
                )
                return
            except Exception as exc:  # pragma: no cover - service boundary
                logger.exception("google auth update failed")
                self._send(500, {"ok": False, "status": "error", "reason": str(exc)})
                return
        if path == "/v1/verify/start":
            try:
                payload = self._read_json_body()
                engine = str(payload.get("engine", "google")).strip().lower()
                url = str(payload.get("url", "")).strip() or None
                force_new = bool(payload.get("force_new", False))
                status = self.server.manager.verify_start(
                    engine=engine, url=url, force_new=force_new
                )
                self._send(200 if status.get("ok") else 400, status)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send(
                    400, {"ok": False, "status": "invalid_request", "reason": str(exc)}
                )
            except Exception as exc:  # pragma: no cover - service boundary
                logger.exception("browser verify start failed")
                self._send(500, {"ok": False, "status": "error", "reason": str(exc)})
            return
        if path == "/v1/verify/input":
            try:
                payload = self._read_json_body()
                status = self.server.manager.verify_input(payload)
                self._send(200 if status.get("ok") else 400, status)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send(
                    400, {"ok": False, "status": "invalid_request", "reason": str(exc)}
                )
            except Exception as exc:  # pragma: no cover - service boundary
                logger.exception("browser verify input failed")
                self._send(500, {"ok": False, "status": "error", "reason": str(exc)})
            return
        if path == "/v1/verify/complete":
            try:
                payload = self._read_json_body()
                engine = str(payload.get("engine", "google")).strip().lower()
                close_session = bool(payload.get("close_session", True))
                status = self.server.manager.verify_complete(
                    engine=engine, close_session=close_session
                )
                self._send(200 if status.get("ok") else 400, status)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send(
                    400, {"ok": False, "status": "invalid_request", "reason": str(exc)}
                )
            except Exception as exc:  # pragma: no cover - service boundary
                logger.exception("browser verify complete failed")
                self._send(500, {"ok": False, "status": "error", "reason": str(exc)})
            return
        if path == "/v1/verify/close":
            try:
                status = self.server.manager.verify_close()
                self._send(200, status)
            except Exception as exc:  # pragma: no cover - service boundary
                logger.exception("browser verify close failed")
                self._send(500, {"ok": False, "status": "error", "reason": str(exc)})
            return
        if path != "/v1/search":
            self._send(404, {"ok": False, "error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 64 * 1024:
                raise ValueError("invalid request body size")
            payload = json.loads(self.rfile.read(length))
            query = str(payload.get("query", "")).strip()
            if not query or len(query) > 2000:
                raise ValueError("query must contain 1-2000 characters")
            engine = str(payload.get("engine", "google")).strip().lower()
            if engine not in {"google", "duckduckgo"}:
                raise ValueError(f"unsupported browser search engine: {engine}")
            request = SearchRequest(
                query=query,
                pageno=max(1, min(int(payload.get("pageno", 1)), 50)),
                locale=str(payload.get("locale", "en-US"))[:32],
                safesearch=max(0, min(int(payload.get("safesearch", 0)), 2)),
                time_range=payload.get("time_range") or None,
                engine=engine,
            )
            result = self.server.manager.search(request)
            self._send(200 if result.get("ok") else 502, result)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._send(
                400, {"ok": False, "status": "invalid_request", "reason": str(exc)}
            )
        except Exception as exc:  # pragma: no cover - service boundary
            logger.exception("browser search request failed")
            self._send(500, {"ok": False, "status": "error", "reason": str(exc)})


def main() -> None:
    config = _config()
    if not config.get("enabled", False):
        raise SystemExit("browser_search.enabled is false")
    logging.basicConfig(level=logging.INFO)
    host = str(config.get("bind_address", "127.0.0.1"))
    port = int(config.get("port", 8890))
    manager = BrowserSearchDispatcher(config)
    server = BrowserSearchHTTPServer((host, port), manager)

    def request_shutdown(*_: Any) -> None:
        # shutdown() must run outside serve_forever's thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    logger.info("browser search worker listening on %s:%s", host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        manager.close()


if __name__ == "__main__":
    main()
