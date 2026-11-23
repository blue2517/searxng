# SPDX-License-Identifier: AGPL-3.0-or-later
"""DuckDuckGo search through the server-side browser search worker."""

from __future__ import annotations

import typing as t

from searx.browser_search.engine_client import (
    build_browser_search_request,
    parse_browser_search_response,
)
from searx.enginelib import EngineAbout
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
    build_browser_search_request("duckduckgo", query, params)


def response(resp: "SXNG_Response") -> EngineResults:
    return parse_browser_search_response(resp, include_domain=False)
