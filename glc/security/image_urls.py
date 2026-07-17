"""Safe fetching for user-supplied image URLs.

The gateway accepts remote images for vision requests.  Those requests run
from the gateway's network position, so every destination must resolve only
to publicly routable addresses before a connection is attempted.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import socket
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

MAX_REDIRECTS = 5
MAX_IMAGE_BYTES = 10 * 1024 * 1024
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class ImageURLFetchError(ValueError):
    """Raised when a remote image URL is unsafe or cannot be fetched."""


@dataclass(frozen=True)
class _ValidatedDestination:
    hostname: str
    address: str
    host_header: str


def _normalize_hostname(hostname: str) -> str:
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ImageURLFetchError("image URL contains an invalid host") from exc


def _allowed_hosts() -> frozenset[str]:
    """Return the exact remote-image host allowlist configured by the operator."""
    configured = os.getenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "")
    return frozenset(_normalize_hostname(host.strip()) for host in configured.split(",") if host.strip())


async def _resolve_addresses(hostname: str, port: int) -> Sequence[str]:
    """Resolve every stream address for a destination without blocking the event loop."""
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ImageURLFetchError(f"could not resolve image host {hostname!r}") from exc

    return tuple({result[4][0] for result in results})


async def _validate_public_destination(url: str) -> _ValidatedDestination:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ImageURLFetchError("invalid image URL") from exc

    if parsed.scheme not in {"http", "https"}:
        raise ImageURLFetchError("image URL must use http or https")
    if not parsed.hostname:
        raise ImageURLFetchError("image URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ImageURLFetchError("image URL must not include credentials")

    hostname = _normalize_hostname(parsed.hostname)
    if hostname not in _allowed_hosts():
        raise ImageURLFetchError(f"image host {hostname!r} is not allowlisted")

    resolved = await _resolve_addresses(hostname, port or (443 if parsed.scheme == "https" else 80))
    if not resolved:
        raise ImageURLFetchError(f"image host {hostname!r} resolved to no addresses")

    public_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_address in resolved:
        # getaddrinfo may include an IPv6 scope identifier (for example
        # ``fe80::1%eth0``).  The address itself is enough for classification.
        address = raw_address.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:  # pragma: no cover - getaddrinfo should only return IP literals
            raise ImageURLFetchError(f"resolver returned an invalid address for {hostname!r}") from exc
        if not ip.is_global:
            raise ImageURLFetchError(
                f"image host {hostname!r} resolves to non-public address {ip.compressed!r}"
            )
        public_addresses.append(ip)

    selected = min(public_addresses, key=lambda value: (value.version, int(value)))
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        host_header = f"{host_header}:{port}"
    return _ValidatedDestination(
        hostname=hostname,
        address=selected.compressed,
        host_header=host_header,
    )


def _pinned_url(url: str, destination: _ValidatedDestination) -> httpx.URL:
    return httpx.URL(url).copy_with(host=destination.address)


async def _read_bounded_body(response: httpx.Response) -> bytes:
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_IMAGE_BYTES:
                raise ImageURLFetchError(f"image response exceeds {MAX_IMAGE_BYTES} bytes")
        except ValueError:
            pass

    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > MAX_IMAGE_BYTES:
            raise ImageURLFetchError(f"image response exceeds {MAX_IMAGE_BYTES} bytes")
        body.extend(chunk)
    return bytes(body)


async def fetch_image_as_data_url(
    url: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """Fetch a public HTTP(S) image and return an inline data URL.

    Remote hosts must be listed exactly in ``GLC_IMAGE_URL_ALLOWED_HOSTS``.
    Redirects are followed manually so the allowlist and resolved addresses are
    validated before each request.  Automatic environment proxies are disabled
    so they cannot bypass destination validation.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; GLCv1/0.1; +image-resolver)",
        "Accept": "image/*,*/*;q=0.8",
    }
    current_url = url

    async with httpx.AsyncClient(
        timeout=30,
        follow_redirects=False,
        headers=headers,
        transport=transport,
        trust_env=False,
    ) as client:
        for redirect_count in range(MAX_REDIRECTS + 1):
            destination = await _validate_public_destination(current_url)
            request_headers = {"Host": destination.host_header}
            extensions = (
                {"sni_hostname": destination.hostname} if urlsplit(current_url).scheme == "https" else None
            )
            try:
                async with client.stream(
                    "GET",
                    _pinned_url(current_url, destination),
                    headers=request_headers,
                    extensions=extensions,
                ) as response:
                    if response.status_code in REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location:
                            raise ImageURLFetchError("image redirect is missing a Location header")
                        if redirect_count == MAX_REDIRECTS:
                            raise ImageURLFetchError(f"image URL exceeded {MAX_REDIRECTS} redirects")
                        current_url = urljoin(current_url, location)
                        continue

                    try:
                        response.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        raise ImageURLFetchError(str(exc)) from exc

                    media_type = (
                        (response.headers.get("content-type") or "image/png").split(";", 1)[0].strip()
                    )
                    content = await _read_bounded_body(response)
            except httpx.HTTPError as exc:
                raise ImageURLFetchError(str(exc)) from exc
            encoded = base64.b64encode(content).decode()
            return f"data:{media_type};base64,{encoded}"

    raise ImageURLFetchError(f"image URL exceeded {MAX_REDIRECTS} redirects")  # pragma: no cover
