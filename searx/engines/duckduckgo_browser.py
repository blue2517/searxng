# SPDX-License-Identifier: AGPL-3.0-or-later
"""DuckDuckGo search through the server-side browser search worker."""

from __future__ import annotations

import typing as t

from searx import get_setting
from searx.enginelib import EngineAbout
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


categories = ["general", "web"]
paging = True
max_page = 50
time_range_support = True
language_support = True
safesearch = True
# The engine talks to the loopback browser worker over HTTP.
enable_http = True

about = EngineAbout(
    website="https://duckduckgo.com",
    wikidata_id="Q12805",
    official_api_documentation="https://duckduckgo.com/duckduckgo-help-pages/settings/params/",
    use_official_api=False,
    require_api_key=False,
    results="JSON",
)


def request(query: str, params: "OnlineParams") -> None:
    config = get_setting("browser_search", {})
    endpoint = str(config.get("endpoint", "http://127.0.0.1:8890")).rstrip("/")
    params["method"] = "POST"
    params["url"] = endpoint + "/v1/search"
    params["headers"]["Content-Type"] = "application/json"
    params["json"] = {
        "engine": "duckduckgo",
        "query": query,
        "pageno": params["pageno"],
        "locale": params.get("searxng_locale", "en-US"),
        "safesearch": params["safesearch"],
        "time_range": params["time_range"],
    }


def response(resp: "SXNG_Response") -> EngineResults:
    try:
        payload = resp.json()
    except Exception as exc:
        raise SearxEngineResponseException(
            "browser worker returned invalid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise SearxEngineResponseException(
            "browser worker returned a non-object JSON response"
        )

    if not payload.get("ok"):
        status = payload.get("status")
        reason = str(payload.get("reason", "browser worker failed"))
        if status == "blocked":
            if "captcha" in reason or "challenge" in reason:
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
        results.append(
            {
                "url": url,
                "title": title,
                "content": str(item.get("content", "")).strip(),
            }
        )
    return results
