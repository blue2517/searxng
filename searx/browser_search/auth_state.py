# SPDX-License-Identifier: AGPL-3.0-or-later
"""Helpers for importing, storing, and inspecting Google search auth state."""

from __future__ import annotations

from datetime import datetime, timezone
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlparse

GOOGLE_AUTH_COOKIE_NAMES = frozenset(
    {
        "SID",
        "HSID",
        "SSID",
        "APISID",
        "SAPISID",
        "__Secure-1PSID",
        "__Secure-3PSID",
        "__Secure-1PAPISID",
        "__Secure-3PAPISID",
    }
)

GOOGLE_CORE_SESSION_COOKIES = frozenset(
    {"SID", "HSID", "SSID", "__Secure-1PSID", "__Secure-3PSID"}
)

GOOGLE_HTTPONLY_COOKIE_NAMES = frozenset(
    {
        "HSID",
        "SSID",
        "SID",
        "__Secure-1PSID",
        "__Secure-3PSID",
        "__Secure-1PSIDTS",
        "__Secure-1PSIDRTS",
        "__Secure-3PSIDTS",
        "__Secure-3PSIDRTS",
        "__Secure-STRP",
        "NID",
        "AEC",
        "SIDCC",
        "__Secure-1PSIDCC",
        "__Secure-3PSIDCC",
        "SOCS",
    }
)

_DEFAULT_IMPORT_TTL_SECONDS = 180 * 86400


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_google_auth_path(config: dict[str, Any] | None = None) -> Path:
    cfg = config or {}
    configured = str(cfg.get("google_auth_state_file", "")).strip()
    if configured:
        return Path(configured)
    profile_dir = (
        str(cfg.get("profile_dir", "")).strip() or "/var/lib/searxng/browser-profiles"
    )
    return Path(profile_dir) / "google-auth-state.json"


def meta_path_for(auth_path: Path) -> Path:
    return auth_path.with_name(f"{auth_path.stem}.meta.json")


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


def has_google_auth_cookies(cookies: list[dict[str, Any]] | None) -> bool:
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", "")).strip()
        value = str(cookie.get("value", "")).strip()
        if not value or name not in GOOGLE_CORE_SESSION_COOKIES:
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


def _normalize_same_site(raw: Any, *, name: str = "", secure: bool = False) -> str:
    text = str(raw or "").strip().lower()
    if text in {"strict"}:
        return "Strict"
    if text in {"lax"}:
        return "Lax"
    if text in {"none", "no_restriction"}:
        return "None"
    if name.startswith("__Secure-3P") and secure:
        return "None"
    return "Lax"


def _normalize_expires(raw: Any, *, default_ttl: int | None = None) -> float | int:
    if raw is None or raw == "":
        return (time.time() + default_ttl) if default_ttl else -1
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return (time.time() + default_ttl) if default_ttl else -1
    if value <= 0:
        return (time.time() + default_ttl) if default_ttl else -1
    return value


def _normalize_cookie(
    item: dict[str, Any],
    *,
    default_domain: str = ".google.com",
    default_ttl: int | None = _DEFAULT_IMPORT_TTL_SECONDS,
) -> dict[str, Any] | None:
    name = str(item.get("name", "")).strip()
    value = item.get("value")
    if not name or value is None:
        return None
    value_str = str(value)
    if value_str == "":
        return None

    url = str(item.get("url", "")).strip()
    domain = str(item.get("domain", "")).strip()
    path = str(item.get("path", "")).strip() or "/"
    secure = bool(item.get("secure", False))
    http_only = bool(item.get("httpOnly", item.get("http_only", False)))

    if name.startswith("__Secure-") or name.startswith("__Host-"):
        secure = True

    if name.startswith("__Host-"):
        host = (urlparse(url).hostname if url else domain).lstrip(".") or "www.google.com"
        if not is_google_cookie_domain(host):
            return None
        cookie: dict[str, Any] = {
            "name": name,
            "value": value_str,
            "url": f"https://{host}/",
            "httpOnly": http_only,
            "secure": True,
            "sameSite": _normalize_same_site(
                item.get("sameSite"), name=name, secure=True
            ),
            "expires": _normalize_expires(
                item.get("expires", item.get("expirationDate")),
                default_ttl=default_ttl,
            ),
        }
        return cookie

    if not domain and url:
        domain = urlparse(url).hostname or ""
    if not domain:
        domain = default_domain
    if not is_google_cookie_domain(domain):
        return None

    same_site = _normalize_same_site(
        item.get("sameSite"), name=name, secure=secure
    )
    if same_site == "None":
        secure = True

    expires = _normalize_expires(
        item.get("expires", item.get("expirationDate")),
        default_ttl=None if item.get("session") is True else default_ttl,
    )
    return {
        "name": name,
        "value": value_str,
        "domain": domain,
        "path": path,
        "expires": expires,
        "httpOnly": http_only,
        "secure": secure,
        "sameSite": same_site,
    }


def _parse_cookie_header(raw_text: str) -> list[dict[str, Any]]:
    text = raw_text.strip()
    if text.lower().startswith("cookie:"):
        text = text.split(":", 1)[1].strip()
    # Strip surrounding quotes if pasted from a curl command or header copy.
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1].strip()

    parsed_pairs: list[tuple[str, str]] = []
    for segment in text.replace("\r", "").replace("\n", ";").split(";"):
        part = segment.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            continue
        parsed_pairs.append((name, value))

    if not parsed_pairs:
        simple = SimpleCookie()
        simple.load(text)
        for name, morsel in simple.items():
            if name and morsel.value:
                parsed_pairs.append((name, morsel.value))

    cookies: list[dict[str, Any]] = []
    for name, value in parsed_pairs:
        secure = True
        same_site = "None" if name.startswith("__Secure-3P") else "Lax"
        normalized = _normalize_cookie(
            {
                "name": name,
                "value": value,
                "domain": ".google.com",
                "path": "/",
                "secure": secure,
                "httpOnly": name in GOOGLE_HTTPONLY_COOKIE_NAMES,
                "sameSite": same_site,
            },
            default_ttl=_DEFAULT_IMPORT_TTL_SECONDS,
        )
        if normalized is not None:
            cookies.append(normalized)
    return cookies


def _parse_netscape(raw_text: str) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        http_only = False
        if line.startswith("#HttpOnly_"):
            http_only = True
            line = line[len("#HttpOnly_") :]
        elif line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 7:
            continue
        domain, _flag, path, secure_flag, expires, name, value = fields
        normalized = _normalize_cookie(
            {
                "name": name,
                "value": value,
                "domain": domain,
                "path": path,
                "secure": secure_flag.upper() == "TRUE",
                "httpOnly": http_only or (name in GOOGLE_HTTPONLY_COOKIE_NAMES),
                "expires": expires,
            },
            default_ttl=_DEFAULT_IMPORT_TTL_SECONDS,
        )
        if normalized is not None:
            cookies.append(normalized)
    return cookies


def parse_google_cookies_input(
    raw_text: str, *, require_auth_cookies: bool = True
) -> tuple[dict[str, Any], str]:
    """Parse pasted cookies / storage_state into Playwright storage_state dict."""

    text = str(raw_text or "").strip()
    if not text:
        raise ValueError("Cookie content cannot be empty")

    source_format = "cookie_header"
    origins: list[dict[str, Any]] = []
    cookies: list[dict[str, Any]] = []

    if text.startswith("{") or text.startswith("["):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON cookie payload: {exc}") from exc

        if isinstance(payload, dict):
            raw_cookies = payload.get("cookies")
            if not isinstance(raw_cookies, list):
                raise ValueError("Playwright storage_state JSON must contain a 'cookies' list")
            source_format = "playwright_storage_state"
            raw_origins = payload.get("origins")
            if isinstance(raw_origins, list):
                origins = [
                    origin
                    for origin in raw_origins
                    if isinstance(origin, dict)
                    and is_google_cookie_domain(
                        urlparse(str(origin.get("origin", ""))).hostname
                    )
                ]
        elif isinstance(payload, list):
            raw_cookies = payload
            source_format = "cookie_json"
        else:
            raise ValueError("Unsupported JSON cookie structure")

        for item in raw_cookies:
            if not isinstance(item, dict):
                continue
            normalized = _normalize_cookie(item, default_ttl=_DEFAULT_IMPORT_TTL_SECONDS)
            if normalized is not None:
                cookies.append(normalized)
    elif "\t" in text and any(
        len(line.lstrip("#").split("\t")) == 7
        for line in text.splitlines()
        if line.strip()
    ):
        source_format = "netscape"
        cookies = _parse_netscape(text)
    else:
        source_format = "cookie_header"
        cookies = _parse_cookie_header(text)

    if not cookies:
        raise ValueError("No valid Google cookies found in input")

    # Deduplicate by (name, domain_or_url, path), keeping the latest entry.
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for cookie in cookies:
        scope = str(cookie.get("domain") or cookie.get("url") or "")
        path = str(cookie.get("path") or "/")
        deduped[(str(cookie["name"]), scope, path)] = cookie
    final_cookies = list(deduped.values())

    if require_auth_cookies and not has_google_auth_cookies(final_cookies):
        raise ValueError(
            "Missing core Google session cookies (SID / HSID / SSID / __Secure-1PSID / __Secure-3PSID)"
        )

    return {"cookies": final_cookies, "origins": origins}, source_format


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


def save_google_auth_state(
    auth_path: Path,
    state: dict[str, Any],
    *,
    source_format: str = "unknown",
    last_auth_ok: bool | None = None,
    last_reason: str = "",
) -> dict[str, Any]:
    clean_state = {
        "cookies": list(state.get("cookies", [])),
        "origins": list(state.get("origins", [])),
    }
    _atomic_write_json(auth_path, clean_state)

    meta = read_google_auth_meta(auth_path)
    now = _now_iso()
    if source_format != "refresh":
        meta["imported_at"] = now
        meta["source_format"] = source_format
    meta["updated_at"] = now
    meta["cookie_count"] = len(clean_state["cookies"])
    meta["has_auth_cookies"] = has_google_auth_cookies(clean_state["cookies"])
    if last_auth_ok is not None:
        meta["last_auth_ok"] = last_auth_ok
        meta["last_checked_at"] = now
    elif source_format != "refresh":
        meta["last_auth_ok"] = None
        meta["last_checked_at"] = ""
    if last_reason:
        meta["last_reason"] = last_reason
    elif source_format != "refresh":
        meta["last_reason"] = "imported"
    _atomic_write_json(meta_path_for(auth_path), meta)
    return get_google_auth_status(auth_path)


def update_google_auth_meta(
    auth_path: Path, *, last_auth_ok: bool, last_reason: str
) -> None:
    if not auth_path.exists():
        return
    meta = read_google_auth_meta(auth_path)
    meta["last_auth_ok"] = last_auth_ok
    meta["last_checked_at"] = _now_iso()
    meta["last_reason"] = last_reason
    _atomic_write_json(meta_path_for(auth_path), meta)


def read_google_auth_meta(auth_path: Path) -> dict[str, Any]:
    meta_file = meta_path_for(auth_path)
    if not meta_file.exists():
        return {}
    try:
        data = json.loads(meta_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_google_auth_state(auth_path: Path) -> dict[str, Any] | None:
    if not auth_path.exists():
        return None
    try:
        data = json.loads(auth_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    cookies = data.get("cookies")
    if not isinstance(cookies, list) or not cookies:
        return None
    return {
        "cookies": cookies,
        "origins": data.get("origins") if isinstance(data.get("origins"), list) else [],
    }


def clear_google_auth_state(auth_path: Path) -> dict[str, Any]:
    for target in (auth_path, meta_path_for(auth_path)):
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
    return get_google_auth_status(auth_path)


def get_google_auth_status(auth_path: Path) -> dict[str, Any]:
    state = load_google_auth_state(auth_path)
    meta = read_google_auth_meta(auth_path)
    if not state:
        return {
            "configured": False,
            "cookie_count": 0,
            "has_auth_cookies": False,
            "source_format": "",
            "imported_at": "",
            "updated_at": "",
            "last_checked_at": "",
            "last_auth_ok": None,
            "last_reason": "",
            "state_file": str(auth_path),
        }
    cookies = state["cookies"]
    return {
        "configured": True,
        "cookie_count": len(cookies),
        "has_auth_cookies": has_google_auth_cookies(cookies),
        "source_format": str(meta.get("source_format", "")),
        "imported_at": str(meta.get("imported_at", "")),
        "updated_at": str(meta.get("updated_at", "")),
        "last_checked_at": str(meta.get("last_checked_at", "")),
        "last_auth_ok": meta.get("last_auth_ok"),
        "last_reason": str(meta.get("last_reason", "")),
        "state_file": str(auth_path),
    }


def merge_storage_states(
    base_state: dict[str, Any] | None, override_state: dict[str, Any] | None
) -> dict[str, Any]:
    """Merge Playwright storage_state dicts, letting override_state win on collision."""

    if not base_state:
        return {
            "cookies": list((override_state or {}).get("cookies", [])),
            "origins": list((override_state or {}).get("origins", [])),
        }
    if not override_state:
        return {
            "cookies": list(base_state.get("cookies", [])),
            "origins": list(base_state.get("origins", [])),
        }

    merged_cookies: dict[tuple[str, str, str], dict[str, Any]] = {}
    for source in (base_state, override_state):
        for cookie in source.get("cookies", []) or []:
            if not isinstance(cookie, dict) or not cookie.get("name"):
                continue
            scope = str(cookie.get("domain") or cookie.get("url") or "")
            path = str(cookie.get("path") or "/")
            merged_cookies[(str(cookie["name"]), scope, path)] = cookie

    merged_origins: dict[str, dict[str, Any]] = {}
    for source in (base_state, override_state):
        for origin in source.get("origins", []) or []:
            if not isinstance(origin, dict) or not origin.get("origin"):
                continue
            merged_origins[str(origin["origin"])] = origin

    return {
        "cookies": list(merged_cookies.values()),
        "origins": list(merged_origins.values()),
    }


def extract_google_storage_state(state: dict[str, Any]) -> dict[str, Any]:
    """Extract Google-domain cookies/origins from a Playwright storage_state dict."""

    cookies = []
    for cookie in state.get("cookies", []) or []:
        if not isinstance(cookie, dict):
            continue
        domain = str(cookie.get("domain", "")).strip()
        url = str(cookie.get("url", "")).strip()
        host = domain or (urlparse(url).hostname or "")
        if is_google_cookie_domain(host):
            cookies.append(cookie)

    origins = []
    for origin in state.get("origins", []) or []:
        if not isinstance(origin, dict):
            continue
        host = urlparse(str(origin.get("origin", ""))).hostname or ""
        if is_google_cookie_domain(host):
            origins.append(origin)

    return {"cookies": cookies, "origins": origins}
