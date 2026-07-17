"""Fail-closed outbound-domain policies for isolated slot Sandboxes."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)


def validate_egress_domains(domains: Iterable[str]) -> tuple[str, ...]:
    """Return normalized domains or reject a policy that could widen egress."""
    normalized: list[str] = []
    for raw in domains:
        value = str(raw).strip().lower().rstrip(".")
        if not value:
            raise RuntimeError("egress domain entries must not be empty")
        if "*" in value:
            raise RuntimeError(f"wildcard egress domain {raw!r} is forbidden; declare exact hostnames")
        if "://" in value or "/" in value or "@" in value or ":" in value:
            raise RuntimeError(f"egress domain {raw!r} must be a hostname without scheme, path, or port")
        hostname = value
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise RuntimeError(f"egress domain {raw!r} must not be an IP literal")
        if not _DOMAIN.fullmatch(hostname):
            raise RuntimeError(f"egress domain {raw!r} is not a valid DNS hostname")
        normalized.append(value)
    if not normalized:
        raise RuntimeError("slot launch requires at least one explicit egress domain")
    return tuple(dict.fromkeys(normalized))


def build_slot_egress_allowlist(slot_domains: Iterable[str], gateway_url: str) -> tuple[str, ...]:
    """Add the exact HTTPS gateway hostname to a slot's declared upstreams."""
    declared_domains = validate_egress_domains(slot_domains)
    parsed = urlsplit(gateway_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("deployed gateway URL must be an HTTPS origin")
    if parsed.port not in {None, 443} or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise RuntimeError("deployed gateway URL must not contain a custom port, path, query, or fragment")
    gateway_host = validate_egress_domains((parsed.hostname,))[0]
    return validate_egress_domains((*declared_domains, gateway_host))
