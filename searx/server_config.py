# SPDX-License-Identifier: AGPL-3.0-or-later
"""Server-side settings used by the administrator preferences form."""

from __future__ import annotations

import copy
import os
from pathlib import Path
import tempfile
from typing import Any

import yaml

from . import settings, settings_loader


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
    return {
        "engines": engine_rows,
        "proxy_pool": {
            "enabled": bool(proxy_pool.get("enabled", False)),
            "entries": list(proxy_pool.get("entries", []) or []),
            "max_attempts": min(3, max(1, int(proxy_pool.get("max_attempts", 3)))),
        },
    }


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
    proxy_entries = _valid_proxy_entries(
        str(form.get("http_proxy_pool_entries", "")).splitlines()
    )
    try:
        proxy_max_attempts = int(form.get("http_proxy_pool_max_attempts", 3))
    except (TypeError, ValueError):
        proxy_max_attempts = 3
    proxy_max_attempts = min(3, max(1, proxy_max_attempts))

    proxy_pool = {
        "enabled": form.get("http_proxy_pool_enabled") == "on",
        "entries": proxy_entries,
        "max_attempts": proxy_max_attempts,
    }
    path = settings_file()
    user_cfg = _load_user_settings(path)
    user_cfg["engines"] = _engine_overrides(enabled_names, user_cfg.get("engines"))
    user_cfg.setdefault("outgoing", {})["proxy_pool"] = proxy_pool
    browser_cfg = user_cfg.get("browser_search")
    if isinstance(browser_cfg, dict):
        browser_cfg.pop("enabled", None)
        if not browser_cfg:
            user_cfg.pop("browser_search", None)
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
    return snapshot()
