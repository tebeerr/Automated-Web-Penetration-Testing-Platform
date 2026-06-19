"""SSRF guard: block private IPs, internal hosts, dangerous schemes."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_HOSTS: set[str] = {
    "localhost",
    "0.0.0.0",
    "metadata.google.internal",
    "metadata.azure.com",
}
ALLOWED_SCHEMES: set[str] = {"http", "https"}


class URLValidationError(ValueError):
    pass


def validate_target_url(url: str) -> tuple[str, str]:
    """Validate `url` and return (sanitized_url, hostname).

    Raises URLValidationError on any policy violation.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(f"Disallowed scheme: {parsed.scheme!r}. Use http or https.")

    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL has no hostname.")

    host_lc = hostname.lower()
    if host_lc in BLOCKED_HOSTS:
        raise URLValidationError("Internal/localhost targets are not allowed.")

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise URLValidationError(f"Cannot resolve hostname {hostname!r}: {e}") from e

    for _, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise URLValidationError(
                f"Target {hostname!r} resolves to a private/internal IP ({ip}); refused."
            )

    return url, host_lc
