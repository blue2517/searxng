# SPDX-License-Identifier: AGPL-3.0-or-later
"""SOCKS/HTTP proxy pool handling for the browser search worker."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import threading
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True, slots=True)
class ProxyEndpoint:
    """A proxy endpoint without exposing credentials in its display name."""

    index: int
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @classmethod
    def parse(cls, index: int, value: str) -> "ProxyEndpoint":
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        if scheme == "socks5h":
            scheme = "socks5"
        if scheme not in {"socks5", "http", "https"}:
            raise ValueError(f"unsupported proxy scheme: {scheme or '<empty>'}")
        if not parsed.hostname or not parsed.port:
            raise ValueError("proxy must include a host and port")
        return cls(
            index=index,
            scheme=scheme,
            host=parsed.hostname,
            port=parsed.port,
            username=unquote(parsed.username) if parsed.username else None,
            password=unquote(parsed.password) if parsed.password else None,
        )

    @property
    def key(self) -> str:
        digest = hashlib.sha256(
            f"{self.scheme}://{self.host}:{self.port}".encode()
        ).hexdigest()[:12]
        return f"proxy-{self.index + 1:03d}-{digest}"

    @property
    def display_name(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def playwright_config(self) -> dict[str, str]:
        config = {"server": f"{self.scheme}://{self.host}:{self.port}"}
        if self.username:
            config["username"] = self.username
        if self.password:
            config["password"] = self.password
        return config


class ProxyPool:
    """Rotate configured proxies once per search recovery round."""

    def __init__(self, values: list[str] | tuple[str, ...] | None):
        self._lock = threading.Lock()
        self._entries: list[ProxyEndpoint] = []
        for index, value in enumerate(values or []):
            try:
                self._entries.append(ProxyEndpoint.parse(index, value))
            except (TypeError, ValueError):
                continue
        self._cursor = 0

    @property
    def entries(self) -> tuple[ProxyEndpoint, ...]:
        return tuple(self._entries)

    @property
    def primary(self) -> ProxyEndpoint | None:
        return self._entries[0] if self._entries else None

    def round(self) -> list[ProxyEndpoint]:
        """Return the single active proxy if configured."""

        return [self._entries[0]] if self._entries else []


def resolve_active_proxy(
    browser_cfg: dict | None = None, outgoing_proxy_cfg: dict | None = None
) -> ProxyEndpoint | None:
    """Resolve the single active proxy endpoint, or None for direct connection."""

    bp = (browser_cfg or {}).get("proxy_pool") or {}
    if bp.get("entries"):
        cfg = bp
    else:
        cfg = outgoing_proxy_cfg or {}
    if not bool(cfg.get("enabled", False)):
        return None
    pool = ProxyPool(cfg.get("entries", []))
    return pool.primary
