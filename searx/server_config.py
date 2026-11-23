# SPDX-License-Identifier: AGPL-3.0-or-later
"""Server-side settings used by the administrator preferences form."""

from __future__ import annotations

import copy
import os
from pathlib import Path
import tempfile
from typing import Any

import httpx
import yaml

from . import settings, settings_loader
from .browser_search.auth_state import (
    clear_route_auth_files,
    get_route_login_status,
)
from .browser_search.proxy_pool import resolve_active_proxy


def settings_file() -> Path:
    """Return the user settings file selected by the current environment."""

    runtime_path = os.environ.get(settings_loader.RUNTIME_SETTINGS_ENV)
    if runtime_path:
        return Path(runtime_path)
    configured = os.environ.get("SEARXNG_SETTINGS_PATH")
    if configured and Path(configured).is_file():
        return Path(configured)
    folder = settings_loader.get_user_cfg_folder()
    if folder is None:
        raise RuntimeError("no writable SearXNG settings directory is configured")
    return folder / settings_loader.SETTINGS_YAML


def _load_user_settings(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"use_default_settings": True}
    value = settings_loader.load_yaml(path)
    if not isinstance(value, dict):
        raise RuntimeError("settings.yml must contain a mapping")
    return value


def _valid_proxy_entries(values: list[str] | tuple[str, ...] | None) -> list[str]:
    from urllib.parse import urlsplit

    result: list[str] = []
    for value in values or []:
        candidate = str(value).strip()
        if not candidate:
            continue
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {
            "http",
            "https",
            "socks4",
            "socks5",
            "socks5h",
        }:
            continue
        if not parsed.hostname or not parsed.port:
            continue
        result.append(candidate)
    return list(dict.fromkeys(result))


def _engine_overrides(
    enabled_names: set[str], current: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    overrides = copy.deepcopy(current or [])
    by_name = {
        str(engine.get("name", "")): engine
        for engine in overrides
        if isinstance(engine, dict) and engine.get("name")
    }
    for engine in settings.get("engines", []):
        name = str(engine.get("name", "")).strip()
        if not name:
            continue
        override = by_name.get(name)
        if override is None:
            override = {"name": name}
            overrides.append(override)
            by_name[name] = override
        override["disabled"] = name not in enabled_names
    return overrides


def snapshot() -> dict[str, Any]:
    """Return the effective server settings needed by the administrator UI."""

    engine_rows = []
    for engine in settings.get("engines", []):
        name = str(engine.get("name", "")).strip()
        if not name:
            continue
        engine_rows.append(
            {
                "name": name,
                "enabled": not bool(engine.get("disabled", False)),
                "inactive": bool(engine.get("inactive", False)),
                "categories": (
                    list(engine.get("categories", []))
                    if isinstance(engine.get("categories", []), list)
                    else []
                ),
            }
        )

    proxy_pool = settings.get("outgoing", {}).get("proxy_pool", {}) or {}
    browser_cfg = settings.get("browser_search", {}) or {}
    entries = list(proxy_pool.get("entries", []) or [])
    profile_dir = Path(
        str(browser_cfg.get("profile_dir", "")).strip()
        or "/var/lib/searxng/browser-profiles"
    )
    active_proxy = resolve_active_proxy(browser_cfg, proxy_pool)
    if active_proxy is not None:
        route_name = active_proxy.display_name
        state_path = profile_dir / f"google-{active_proxy.key}" / "storage-state.json"
    else:
        route_name = "direct"
        state_path = profile_dir / "google-direct" / "storage-state.json"
    google_auth = get_route_login_status(state_path, route_name=route_name)
    return {
        "engines": engine_rows,
        "proxy_pool": {
            "enabled": bool(proxy_pool.get("enabled", False)),
            "entries": entries[:1],
            "proxy": entries[0] if entries else "",
        },
        "browser_search_enabled": bool(browser_cfg.get("enabled", False)),
        "google_auth": google_auth,
    }


def _notify_browser_worker(path: str, payload: dict[str, Any]) -> None:
    browser_cfg = settings.get("browser_search", {}) or {}
    if not browser_cfg.get("enabled"):
        return
    endpoint = str(browser_cfg.get("endpoint", "http://127.0.0.1:8890")).strip().rstrip("/")
    if not endpoint:
        return
    try:
        httpx.post(f"{endpoint}{path}", json=payload, timeout=5.0)
    except Exception:
        pass


def clear_google_auth() -> dict[str, Any]:
    """Clear saved Google browser session state and reset cached Google contexts."""

    browser_cfg = settings.get("browser_search", {}) or {}
    proxy_pool = settings.get("outgoing", {}).get("proxy_pool", {}) or {}
    profile_dir = Path(
        str(browser_cfg.get("profile_dir", "")).strip()
        or "/var/lib/searxng/browser-profiles"
    )
    clear_route_auth_files(profile_dir)
    _notify_browser_worker("/v1/auth/google", {"action": "clear"})
    active_proxy = resolve_active_proxy(browser_cfg, proxy_pool)
    if active_proxy is not None:
        route_name = active_proxy.display_name
        state_path = profile_dir / f"google-{active_proxy.key}" / "storage-state.json"
    else:
        route_name = "direct"
        state_path = profile_dir / "google-direct" / "storage-state.json"
    return get_route_login_status(state_path, route_name=route_name)


def _write_yaml(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            yaml.safe_dump(
                value,
                stream,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def save(form: Any) -> dict[str, Any]:
    """Persist server settings from a Flask form and apply them immediately."""

    enabled_names = {
        str(value).strip()
        for key, value in form.items()
        if str(key).startswith("server_engine__") and str(value).strip()
    }
    raw_proxy = form.get("http_proxy_url")
    if raw_proxy is None:
        raw_proxy = form.get("http_proxy_pool_entries", "")
    proxy_entries = _valid_proxy_entries(str(raw_proxy).splitlines())[:1]

    proxy_pool = {
        "enabled": form.get("http_proxy_pool_enabled") == "on",
        "entries": proxy_entries,
    }
    path = settings_file()
    user_cfg = _load_user_settings(path)
    user_cfg["engines"] = _engine_overrides(enabled_names, user_cfg.get("engines"))
    user_cfg.setdefault("outgoing", {})["proxy_pool"] = proxy_pool
    _write_yaml(path, user_cfg)

    # Apply the same effective values to this process.  A service manager still
    # owns separately managed helper processes such as the browser worker.
    for engine in settings.get("engines", []):
        name = str(engine.get("name", ""))
        engine["disabled"] = name not in enabled_names
        if name in enabled_names:
            engine["inactive"] = False
    settings.setdefault("outgoing", {})["proxy_pool"] = copy.deepcopy(proxy_pool)

    from . import search

    search.initialize(
        settings_engines=settings.get("engines", []),
        check_network=False,
        enable_metrics=bool(settings.get("general", {}).get("enable_metrics", True)),
    )
    _notify_browser_worker("/v1/config/reload", {"proxy_pool": proxy_pool})
    return snapshot()
