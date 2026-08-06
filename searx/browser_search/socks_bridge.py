# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local SOCKS5 bridge for upstream SOCKS5 endpoints with authentication."""

from __future__ import annotations

import logging
import select
import socket
import socketserver
import threading
from typing import Any

from .proxy_pool import ProxyEndpoint

logger = logging.getLogger(__name__)


def _read_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("SOCKS5 peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_socks_address(connection: socket.socket, address_type: int) -> bytes:
    if address_type == 1:
        return _read_exact(connection, 4)
    if address_type == 3:
        length = _read_exact(connection, 1)
        return length + _read_exact(connection, length[0])
    if address_type == 4:
        return _read_exact(connection, 16)
    raise ValueError(f"unsupported SOCKS5 address type: {address_type}")


def _socks_reply(connection: socket.socket, reply_code: int) -> None:
    connection.sendall(b"\x05" + bytes([reply_code]) + b"\x00\x01" + b"\x00" * 6)


class _BridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], bridge: "Socks5AuthBridge"):
        self.bridge = bridge
        super().__init__(address, _BridgeHandler)


class _BridgeHandler(socketserver.BaseRequestHandler):
    server: _BridgeServer

    def handle(self) -> None:
        self.server.bridge.handle(self.request)


class Socks5AuthBridge:
    """Expose an unauthenticated local SOCKS5 port for one authenticated route."""

    def __init__(self, upstream: ProxyEndpoint):
        if upstream.scheme != "socks5" or not upstream.username:
            raise ValueError(
                "a SOCKS5 username is required for the authentication bridge"
            )
        self.upstream = upstream
        self._server: _BridgeServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._server is not None:
            return
        server = _BridgeServer(("127.0.0.1", 0), self)
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"searxng-socks-bridge-{self.upstream.index + 1}",
            daemon=True,
        )
        self._server = server
        self._thread = thread
        thread.start()

    def close(self) -> None:
        server = self._server
        if server is None:
            return
        self._server = None
        server.shutdown()
        server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._thread = None

    def playwright_config(self) -> dict[str, str]:
        if self._server is None:
            self.start()
        assert self._server is not None
        host, port = self._server.server_address
        return {"server": f"socks5://{host}:{port}"}

    def handle(self, client: socket.socket) -> None:
        upstream_socket: socket.socket | None = None
        try:
            client.settimeout(30)
            if _read_exact(client, 1) != b"\x05":
                raise ValueError("local peer is not SOCKS5")
            methods = _read_exact(client, _read_exact(client, 1)[0])
            if 0x00 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")

            header = _read_exact(client, 4)
            if header[0] != 5 or header[1] != 1:
                _socks_reply(client, 7)
                return
            address = _read_socks_address(client, header[3])
            port = _read_exact(client, 2)
            request = header + address + port

            upstream_socket = socket.create_connection(
                (self.upstream.host, self.upstream.port), timeout=30
            )
            upstream_socket.settimeout(30)
            methods = b"\x02\x00" if self.upstream.password is not None else b"\x00"
            upstream_socket.sendall(b"\x05" + bytes([len(methods)]) + methods)
            upstream_method = _read_exact(upstream_socket, 2)
            if upstream_method[0] != 5 or upstream_method[1] == 0xFF:
                raise ConnectionError("upstream SOCKS5 rejected authentication methods")
            if upstream_method[1] == 2:
                username = (self.upstream.username or "").encode("utf-8")
                password = (self.upstream.password or "").encode("utf-8")
                if len(username) > 255 or len(password) > 255:
                    raise ValueError("SOCKS5 credentials are too long")
                upstream_socket.sendall(
                    b"\x01"
                    + bytes([len(username)])
                    + username
                    + bytes([len(password)])
                    + password
                )
                auth_result = _read_exact(upstream_socket, 2)
                if auth_result != b"\x01\x00":
                    raise ConnectionError("upstream SOCKS5 authentication failed")
            elif upstream_method[1] != 0:
                raise ConnectionError("upstream SOCKS5 selected an unsupported method")

            upstream_socket.sendall(request)
            response = _read_exact(upstream_socket, 4)
            response_address = _read_socks_address(upstream_socket, response[3])
            response_port = _read_exact(upstream_socket, 2)
            client.sendall(response + response_address + response_port)
            if response[1] != 0:
                return

            client.settimeout(None)
            upstream_socket.settimeout(None)
            self._relay(client, upstream_socket)
        except (ConnectionError, OSError, ValueError) as exc:
            logger.debug(
                "SOCKS5 bridge request failed for %s: %s",
                self.upstream.display_name,
                exc,
            )
            try:
                _socks_reply(client, 1)
            except OSError:
                pass
        finally:
            if upstream_socket is not None:
                upstream_socket.close()
            client.close()

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket) -> None:
        peers = {left: right, right: left}
        while True:
            readable, _, _ = select.select([left, right], [], [], 60)
            if not readable:
                return
            for source in readable:
                data = source.recv(64 * 1024)
                if not data:
                    return
                peers[source].sendall(data)
