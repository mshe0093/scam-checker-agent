import httpx
import pytest

from scamcheck.tools.netsafety import UnsafeURLError, assert_safe_url
from scamcheck.tools.redirects import resolve_url_redirects

PUBLIC = {
    "bit.ly": ["67.199.248.10"],
    "evil-landing.xyz": ["93.184.215.20"],
    "hop.example": ["93.184.215.30"],
    "internal.corp": ["10.0.0.5"],
}


def resolver(host):
    if host in PUBLIC:
        return PUBLIC[host]
    raise OSError("nxdomain")


def client_for(routes):
    def handler(req: httpx.Request) -> httpx.Response:
        return routes[str(req.url)]

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_shortener_chain_resolved(settings):
    client = client_for(
        {
            "http://bit.ly/abc": httpx.Response(
                301, headers={"location": "https://evil-landing.xyz/login"}
            ),
            "https://evil-landing.xyz/login": httpx.Response(
                200, headers={"content-type": "text/html"}, text="<html>"
            ),
        }
    )
    res = resolve_url_redirects("bit.ly/abc", client=client, resolver=resolver, settings=settings)
    assert res.evidence["final_domain"] == "evil-landing.xyz"
    assert {s.id for s in res.signals} == {"shortener_resolved"}


def test_meta_refresh_followed(settings):
    client = client_for(
        {
            "http://hop.example/": httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text='<meta http-equiv="refresh" content="0; url=https://evil-landing.xyz/x">',
            ),
            "https://evil-landing.xyz/x": httpx.Response(
                200, headers={"content-type": "text/plain"}
            ),
        }
    )
    res = resolve_url_redirects(
        "http://hop.example/", client=client, resolver=resolver, settings=settings
    )
    assert res.evidence["final_url"] == "https://evil-landing.xyz/x"
    assert "cross_domain_redirects" in {s.id for s in res.signals}


def test_redirect_into_private_network_is_blocked(settings):
    client = client_for(
        {
            "http://hop.example/": httpx.Response(
                302, headers={"location": "http://internal.corp/admin"}
            ),
        }
    )
    res = resolve_url_redirects(
        "http://hop.example/", client=client, resolver=resolver, settings=settings
    )
    assert res.status == "unverified"
    assert "unsafe_destination" in {s.id for s in res.signals}


def test_unreachable_is_unverified(settings):
    def boom(req):
        raise httpx.ConnectError("refused")

    client = httpx.Client(transport=httpx.MockTransport(boom))
    res = resolve_url_redirects(
        "http://hop.example/", client=client, resolver=resolver, settings=settings
    )
    assert res.status == "unverified"
    assert "not evidence" in res.summary


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "http://hop.example:8080/",
        "http://user:pw@hop.example/",
        "http://[::1]/",
    ],
)
def test_ssrf_guard_rejects(url):
    with pytest.raises(UnsafeURLError):
        assert_safe_url(url, resolver)


def test_ssrf_guard_allows_public():
    assert assert_safe_url("https://hop.example/path", resolver) == "hop.example"


def test_dead_link_is_info_not_unsafe(settings):
    res = resolve_url_redirects(
        "http://nxdomain.example/", client=client_for({}), resolver=resolver, settings=settings
    )
    assert res.status == "unverified"
    assert {s.id for s in res.signals} == {"host_does_not_resolve"}
