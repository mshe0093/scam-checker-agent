from __future__ import annotations

import httpx
import pytest

from scamcheck.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(model="test-model", safe_browsing_key=None)


def rdap_404_client() -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(404, json={})))


def rdap_client(created: str) -> httpx.Client:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": created}]}
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


def fake_whois(text: str):
    return lambda server, query: text
