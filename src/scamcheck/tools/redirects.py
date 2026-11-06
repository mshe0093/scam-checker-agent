"""resolve_url_redirects: follow a link's redirect chain server-side so the user never has to click.

Safety: redirects are followed manually and EVERY hop goes through the SSRF guard (public IPs only,
http/https, ports 80/443). Bodies are never rendered; at most 32 KB is read to spot meta-refresh.
Known limitation: DNS can change between the guard's lookup and httpx's connect (DNS rebinding).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from scamcheck.config import Settings, get_settings
from scamcheck.models import Severity, Signal, Status, ToolResult
from scamcheck.tools.domain import SHORTENERS, host_of, registrable
from scamcheck.tools.netsafety import Resolver, UnsafeURLError, assert_safe_url, system_resolver

MAX_HOPS = 8
MAX_BODY = 32_768
_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)""",
    re.IGNORECASE,
)


def _normalise(url: str) -> str:
    url = url.strip()
    return url if re.match(r"^https?://", url, re.I) else "http://" + url


def resolve_url_redirects(
    url: str,
    *,
    client: httpx.Client | None = None,
    resolver: Resolver = system_resolver,
    settings: Settings | None = None,
) -> ToolResult:
    """Follow redirects (HTTP 3xx and meta-refresh) to the final destination without rendering."""
    settings = settings or get_settings()
    current = _normalise(url)
    chain: list[dict] = []
    signals: list[Signal] = []
    own_client = client is None
    client = client or httpx.Client(
        timeout=settings.http_timeout,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=False,
    )
    final_status: int | None = None
    try:
        for _ in range(MAX_HOPS):
            try:
                assert_safe_url(current, resolver)
            except UnsafeURLError as exc:
                signals.append(
                    Signal(
                        id="unsafe_destination",
                        severity=Severity.AMBER,
                        detail=f"Stopped before fetching {current}: {exc}.",
                    )
                )
                return _result(
                    url,
                    chain,
                    current,
                    None,
                    signals,
                    Status.UNVERIFIED,
                    f"Did not fetch {current} ({exc}).",
                )
            try:
                with client.stream("GET", current, follow_redirects=False) as resp:
                    final_status = resp.status_code
                    chain.append({"url": current, "status": resp.status_code})
                    location = resp.headers.get("location")
                    if resp.is_redirect and location:
                        current = urljoin(current, location)
                        continue
                    body = b""
                    ctype = resp.headers.get("content-type", "")
                    if "html" in ctype:
                        for chunk in resp.iter_bytes():
                            body += chunk
                            if len(body) >= MAX_BODY:
                                break
                    meta = _META_REFRESH.search(body.decode("utf-8", errors="ignore"))
                    if meta:
                        current = urljoin(current, meta.group(1))
                        chain[-1]["via"] = "meta-refresh"
                        continue
                    break
            except httpx.HTTPError as exc:
                chain.append({"url": current, "error": type(exc).__name__})
                return _result(
                    url,
                    chain,
                    current,
                    None,
                    signals,
                    Status.UNVERIFIED,
                    f"Could not reach {host_of(current)} ({type(exc).__name__}). "
                    "Phishing sites are often taken down quickly; this is not evidence "
                    "either way.",
                )
        else:
            signals.append(
                Signal(
                    id="too_many_redirects",
                    severity=Severity.AMBER,
                    detail=f"More than {MAX_HOPS} redirects, which is typical of cloaking chains.",
                )
            )
    finally:
        if own_client:
            client.close()

    return _result(url, chain, current, final_status, signals, Status.OK, None)


def _result(
    original: str,
    chain: list[dict],
    final_url: str,
    final_status: int | None,
    signals: list[Signal],
    status: Status,
    summary: str | None,
) -> ToolResult:
    start = registrable(host_of(original))
    end = registrable(host_of(final_url))
    hosts = []
    for hop in chain:
        h = registrable(host_of(hop["url"]))
        if h not in hosts:
            hosts.append(h)
    if start in SHORTENERS:
        signals.append(
            Signal(
                id="shortener_resolved",
                severity=Severity.INFO,
                detail=f"Shortened link ({start}) resolves to {end}.",
            )
        )
    if len(hosts) > 2 or (start != end and start not in SHORTENERS and len(chain) > 1):
        signals.append(
            Signal(
                id="cross_domain_redirects",
                severity=Severity.AMBER,
                detail="Link bounces across domains: " + " → ".join(hosts),
            )
        )
    return ToolResult(
        tool="resolve_url_redirects",
        status=status,
        summary=summary
        or (
            f"{original} → {final_url} ({len(chain)} hop(s), final HTTP {final_status}). "
            f"Run check_domain on {end}."
            if start != end
            else f"No redirect to another domain; final HTTP {final_status}."
        ),
        signals=signals,
        evidence={"chain": chain, "final_url": final_url, "final_domain": end},
    )
