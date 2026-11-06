"""Outbound-request safety: an SSRF guard for anything that fetches attacker-supplied URLs."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {None, 80, 443}

Resolver = Callable[[str], list[str]]


class UnsafeURLError(ValueError):
    """Raised when a URL must not be fetched (private address, odd port, bad scheme...)."""


class UnresolvableHostError(UnsafeURLError):
    """The host has no DNS records: nothing to fetch, but not a safety problem either."""


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def assert_safe_url(url: str, resolver: Resolver = system_resolver) -> str:
    """Validate scheme/port and that the host resolves only to public IPs. Returns the hostname."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme '{parts.scheme}' not allowed")
    if parts.username or parts.password:
        raise UnsafeURLError("URLs with embedded credentials are not fetched")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeURLError("invalid port") from exc
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError(f"port {port} not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeURLError("no host")
    try:
        ips = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            ips = resolver(host)
        except OSError as exc:
            raise UnresolvableHostError(f"{host} does not resolve in DNS") from exc
    if not ips:
        raise UnresolvableHostError(f"{host} does not resolve in DNS")
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise UnsafeURLError(f"{host} resolves to non-public address {bad[0]}")
    return host
