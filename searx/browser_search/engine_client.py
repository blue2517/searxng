# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared request/response helpers for browser-backed SearXNG engines."""

from __future__ import annotations

import typing as t

from searx import get_setting
from searx.exceptions import (
    SearxEngineAccessDeniedException,
    SearxEngineCaptchaException,
    SearxEngineResponseException,
    SearxEngineTooManyRequestsException,
)
from searx.result_types import EngineResults

if t.TYPE_CHECKING:
    from searx.extended_types import SXNG_Response
    from searx.search.processors import OnlineParams


_CAPTCHA_REASON_MARKERS = (
    "captcha",
    "challenge",
    "unusual_traffic",
    "consent",
    "verification_in_progress",
)


def build_browser_search_request(
    engine: str, query: str, params: "OnlineParams"
) -> None:
    """Populate SearXNG HTTP request params for the local browser search worker."""

    config = get_setting("browser_search", {})
    endpoint = str(config.get("endpoint", "http://127.0.0.1:8890")).rstrip("/")
    params["method"] = "POST"
    params["url"] = endpoint + "/v1/search"
    params["headers"]["Content-Type"] = "application/json"
    # The worker uses HTTP 502 with a structured JSON payload to report
    # blocked/challenge/rate_limited states; disable raise_for_httperror so
    # response() can classify CAPTCHAs instead of surfacing a raw 502 error.
    params["raise_for_httperror"] = False
    params["json"] = {
        "engine": engine,
        "query": query,
        "pageno": params["pageno"],
        "locale": params.get("searxng_locale", "auto"),
        "safesearch": params["safesearch"],
        "time_range": params["time_range"],
    }


def parse_browser_search_response(
    resp: "SXNG_Response", *, include_domain: bool = False
) -> EngineResults:
    """Parse the browser search worker JSON response into EngineResults."""

    try:
        payload = resp.json()
    except Exception as exc:
        status_code = getattr(resp, "status_code", None)
        detail = f" (HTTP {status_code})" if status_code else ""
        raise SearxEngineResponseException(
            f"browser worker returned invalid JSON{detail}"
        ) from exc
    if not isinstance(payload, dict):
        raise SearxEngineResponseException(
            "browser worker returned a non-object JSON response"
        )

    if not payload.get("ok"):
        status = payload.get("status")
        reason = str(payload.get("reason", "browser worker failed"))
        reason_lower = reason.lower()
        if status == "blocked":
            if any(marker in reason_lower for marker in _CAPTCHA_REASON_MARKERS):
                raise SearxEngineCaptchaException(message=reason, suspended_time=120)
            raise SearxEngineAccessDeniedException(message=reason, suspended_time=120)
        if status == "rate_limited":
            raise SearxEngineTooManyRequestsException(
                message=reason, suspended_time=120
            )
        raise SearxEngineResponseException(reason)

    results = EngineResults()
    for item in payload.get("results", []):
        url = str(item.get("url", "")).strip()
        title = str(item.get("title", "")).strip()
        if not url or not title:
            continue
        res_item: dict[str, t.Any] = {
            "url": url,
            "title": title,
            "content": str(item.get("content", "")).strip(),
        }
        if include_domain:
            domain = str(item.get("domain", "")).strip()
            if domain:
                res_item["domain"] = domain
        results.append(res_item)
    return results
