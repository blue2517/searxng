# SPDX-License-Identifier: AGPL-3.0-or-later
"""Helpers for inspecting and managing browser-native Google login sessions."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlparse

GOOGLE_CORE_SESSION_COOKIES = frozenset(
    {"SID", "HSID", "SSID", "__Secure-1PSID", "__Secure-3PSID"}
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def is_google_cookie_domain(domain: str | None) -> bool:
    if not domain:
        return False
    host = domain.strip().lower().lstrip(".")
    if not host:
        return False
    if host == "google.com" or host.endswith(".google.com"):
        return True
    parts = host.split(".")
    if len(parts) >= 2 and parts[-2] == "google":
        return True
    if len(parts) >= 3 and parts[-3] == "google" and len(parts[-1]) == 2:
        return True
    return False


def _cookie_not_expired(cookie: dict[str, Any], now: float | None = None) -> bool:
    raw_expires = cookie.get("expires")
    if raw_expires is None or raw_expires == "":
        return True
    try:
        expires = float(raw_expires)
    except (TypeError, ValueError):
        return True
    if expires <= 0:
        return True
    return expires > (time.time() if now is None else now)


def has_google_auth_cookies(cookies: list[dict[str, Any]] | None) -> bool:
    now = time.time()
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", "")).strip()
        value = str(cookie.get("value", "")).strip()
        if not value or name not in GOOGLE_CORE_SESSION_COOKIES:
            continue
        if not _cookie_not_expired(cookie, now):
            continue
        domain = str(cookie.get("domain", "")).strip()
        url = str(cookie.get("url", "")).strip()
        if domain and not is_google_cookie_domain(domain):
            continue
        if not domain and url:
            host = urlparse(url).hostname or ""
            if not is_google_cookie_domain(host):
                continue
        return True
    return False


def _atomic_write_json(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(f"{path.suffix}.tmp")
    temp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    try:
        os.chmod(temp_path, mode)
    except OSError:
        pass
    temp_path.replace(path)


def route_auth_meta_path(state_path: Path) -> Path:
    return state_path.with_name("auth-meta.json")


def read_route_auth_meta(state_path: Path) -> dict[str, Any]:
    meta_file = route_auth_meta_path(state_path)
    if not meta_file.exists():
        return {}
    try:
        data = json.loads(meta_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_route_auth_meta(
    state_path: Path,
    *,
    logged_in: bool | None,
    reason: str = "",
    route: str = "",
) -> dict[str, Any]:
    meta = read_route_auth_meta(state_path)
    now = _now_iso()
    meta["logged_in"] = logged_in
    meta["checked_at"] = now
    meta["updated_at"] = now
    if reason:
        meta["reason"] = reason
    if route:
        meta["route"] = route
    _atomic_write_json(route_auth_meta_path(state_path), meta)
    return meta


def get_route_login_status(
    state_path: Path, *, route_name: str = "direct"
) -> dict[str, Any]:
    cookies: list[dict[str, Any]] = []
    has_session = state_path.exists()
    if has_session:
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("cookies"), list):
                cookies = [
                    c
                    for c in data["cookies"]
                    if isinstance(c, dict)
                    and is_google_cookie_domain(
                        str(c.get("domain", "")).strip()
                        or (urlparse(str(c.get("url", "")).strip()).hostname or "")
                    )
                    and _cookie_not_expired(c)
                ]
        except Exception:
            cookies = []
    meta = read_route_auth_meta(state_path)
    has_auth = has_google_auth_cookies(cookies)
    logged_in = meta.get("logged_in")
    if not has_auth and logged_in is True:
        logged_in = False
    return {
        "route": route_name,
        "has_session": has_session,
        "has_auth_cookies": has_auth,
        "cookie_count": len(cookies),
        "logged_in": logged_in,
        "checked_at": str(meta.get("checked_at", "")),
        "updated_at": str(meta.get("updated_at", "")),
        "reason": str(meta.get("reason", "")),
        "state_file": str(state_path),
    }


def clear_route_auth_files(profile_root: Path) -> None:
    """Remove saved Google route storage states, metadata, and legacy cookie files."""

    for candidate in profile_root.glob("google-*"):
        for filename in ("storage-state.json", "auth-meta.json"):
            try:
                (candidate / filename).unlink(missing_ok=True)
            except OSError:
                pass
    for legacy in ("google-auth-state.json", "google-auth-state.meta.json"):
        try:
            (profile_root / legacy).unlink(missing_ok=True)
        except OSError:
            pass
