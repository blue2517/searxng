# SPDX-License-Identifier: AGPL-3.0-or-later
"""Browser-backed search support for SearXNG."""

__all__ = [
    "BrowserSearchDispatcher",
    "BrowserSearchManager",
    "ProxyEndpoint",
    "ProxyPool",
]

from .manager import BrowserSearchDispatcher, BrowserSearchManager
from .proxy_pool import ProxyEndpoint, ProxyPool
