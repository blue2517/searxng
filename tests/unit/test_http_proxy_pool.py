# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

import httpx

from searx.network.network import Network


def response(
    status: int, text: str = "ok", content_type: str = "text/plain"
) -> httpx.Response:
    return httpx.Response(
        status,
        text=text,
        headers={"content-type": content_type},
        request=httpx.Request("GET", "https://example.test/search"),
    )


class HTTPProxyPoolTests(IsolatedAsyncioTestCase):

    async def test_challenge_rotates_from_direct_to_proxy(self):
        network = Network(
            enable_http=True,
            proxy_pool={
                "enabled": True,
                "max_attempts": 3,
                "entries": [
                    "socks5://proxy-one.test:1080",
                    "http://proxy-two.test:8080",
                ],
            },
        )
        client = AsyncMock()
        client.is_closed = False
        client.request = AsyncMock(side_effect=[response(429), response(200)])
        get_client = AsyncMock(return_value=client)
        with patch.object(Network, "get_client", get_client):
            result = await network.request(
                "GET", "https://example.test/search", raise_for_httperror=False
            )

        self.assertEqual(200, result.status_code)
        self.assertEqual(2, get_client.await_count)
        self.assertIsNone(get_client.await_args_list[0].kwargs["proxy_override"])
        self.assertEqual(
            "socks5://proxy-one.test:1080",
            get_client.await_args_list[1].kwargs["proxy_override"],
        )

    async def test_total_attempts_are_capped_at_three(self):
        network = Network(
            enable_http=True,
            proxy_pool={
                "enabled": True,
                "max_attempts": 9,
                "entries": [
                    "http://proxy-one.test:8080",
                    "http://proxy-two.test:8080",
                    "http://proxy-three.test:8080",
                ],
            },
        )
        client = AsyncMock()
        client.is_closed = False
        client.request = AsyncMock(
            side_effect=[response(403), response(403), response(403)]
        )
        get_client = AsyncMock(return_value=client)
        with patch.object(Network, "get_client", get_client):
            result = await network.request(
                "GET", "https://example.test/search", raise_for_httperror=False
            )

        self.assertEqual(403, result.status_code)
        self.assertEqual(3, get_client.await_count)

    def test_challenge_body_requires_page_level_signal(self):
        ordinary = response(
            200, "Search result discussing captcha libraries", "text/html"
        )
        challenge = response(
            200,
            '<html><form action="/captcha/verify">Verify you are human</form></html>',
            "text/html",
        )

        self.assertFalse(Network._looks_like_challenge(ordinary))
        self.assertTrue(Network._looks_like_challenge(challenge))

    async def test_loopback_urls_never_use_proxy_pool(self):
        network = Network(
            enable_http=True,
            proxy_pool={
                "enabled": True,
                "max_attempts": 3,
                "entries": [
                    "socks5://proxy-one.test:1080",
                    "http://proxy-two.test:8080",
                ],
            },
        )
        client = AsyncMock()
        client.is_closed = False
        client.request = AsyncMock(side_effect=[response(502)])
        get_client = AsyncMock(return_value=client)
        with patch.object(Network, "get_client", get_client):
            result = await network.request(
                "POST", "http://127.0.0.1:8890/v1/search", raise_for_httperror=False
            )

        self.assertEqual(502, result.status_code)
        # Should only try direct (1 attempt) and never rotate to proxy for loopback
        self.assertEqual(1, get_client.await_count)
        self.assertIsNone(get_client.await_args_list[0].kwargs["proxy_override"])
