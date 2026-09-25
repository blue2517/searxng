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
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"ok": True, "service": "browser-search"})
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/search":
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
