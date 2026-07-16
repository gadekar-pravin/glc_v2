"""Regression tests for SSRF protection in the remote-image resolver."""

from __future__ import annotations

import base64

import httpx
import pytest

from glc.security import image_urls


def _set_resolver(monkeypatch, addresses_by_host: dict[str, tuple[str, ...]], calls=None):
    async def resolve(hostname: str, port: int):
        if calls is not None:
            calls.append((hostname, port))
        return addresses_by_host[hostname]

    monkeypatch.setattr(image_urls, "_resolve_addresses", resolve)


@pytest.mark.parametrize(
    "blocked_address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ],
)
async def test_non_public_ipv4_and_ipv6_destinations_are_rejected(monkeypatch, blocked_address):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "blocked.test")
    _set_resolver(monkeypatch, {"blocked.test": (blocked_address,)})
    requested = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requested
        requested = True
        return httpx.Response(200, request=request)

    with pytest.raises(image_urls.ImageURLFetchError, match="non-public address"):
        await image_urls.fetch_image_as_data_url(
            "http://blocked.test/image.png",
            transport=httpx.MockTransport(handler),
        )

    assert requested is False


async def test_every_dns_answer_must_be_public(monkeypatch):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "mixed.test")
    _set_resolver(monkeypatch, {"mixed.test": ("93.184.216.34", "10.0.0.2")})

    with pytest.raises(image_urls.ImageURLFetchError, match="10.0.0.2"):
        await image_urls.fetch_image_as_data_url(
            "https://mixed.test/image.png",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
        )


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("file:///etc/passwd", "must use http or https"),
        ("https:///image.png", "must include a host"),
        ("https://user:password@images.test/image.png", "must not include credentials"),
        ("https://images.test:invalid/image.png", "invalid image URL"),
    ],
)
async def test_malformed_or_unsafe_url_shapes_are_rejected(url, message):
    with pytest.raises(image_urls.ImageURLFetchError, match=message):
        await image_urls.fetch_image_as_data_url(url, transport=httpx.MockTransport(lambda request: None))


async def test_public_image_is_converted_to_data_url(monkeypatch):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "images.test")
    resolver_calls = []
    _set_resolver(monkeypatch, {"images.test": ("93.184.216.34",)}, resolver_calls)
    image = b"GIF89a"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"].startswith("image/")
        return httpx.Response(200, content=image, headers={"content-type": "image/gif; charset=binary"})

    result = await image_urls.fetch_image_as_data_url(
        "https://images.test/pixel.gif",
        transport=httpx.MockTransport(handler),
    )

    assert result == f"data:image/gif;base64,{base64.b64encode(image).decode()}"
    assert resolver_calls == [("images.test", 443)]


async def test_unallowlisted_host_is_rejected_before_dns_or_http(monkeypatch):
    monkeypatch.delenv("GLC_IMAGE_URL_ALLOWED_HOSTS", raising=False)
    resolved = False
    requested = False

    async def resolver(hostname: str, port: int):
        nonlocal resolved
        resolved = True
        return ("93.184.216.34",)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requested
        requested = True
        return httpx.Response(200, request=request)

    monkeypatch.setattr(image_urls, "_resolve_addresses", resolver)

    with pytest.raises(image_urls.ImageURLFetchError, match="is not allowlisted"):
        await image_urls.fetch_image_as_data_url(
            "https://attacker.test/probe",
            transport=httpx.MockTransport(handler),
        )

    assert resolved is False
    assert requested is False


async def test_redirect_destination_is_revalidated_before_second_request(monkeypatch):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "images.test,internal.test")
    resolver_calls = []
    _set_resolver(
        monkeypatch,
        {
            "images.test": ("93.184.216.34",),
            "internal.test": ("169.254.169.254",),
        },
        resolver_calls,
    )
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://internal.test/latest/meta-data"})

    with pytest.raises(image_urls.ImageURLFetchError, match="non-public address"):
        await image_urls.fetch_image_as_data_url(
            "https://images.test/start",
            transport=httpx.MockTransport(handler),
        )

    assert requested_urls == ["https://images.test/start"]
    assert resolver_calls == [("images.test", 443), ("internal.test", 80)]


async def test_public_relative_redirect_is_followed(monkeypatch):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "images.test")
    resolver_calls = []
    _set_resolver(monkeypatch, {"images.test": ("93.184.216.34",)}, resolver_calls)
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final.png"})
        return httpx.Response(200, content=b"png", headers={"content-type": "image/png"})

    result = await image_urls.fetch_image_as_data_url(
        "https://images.test/start",
        transport=httpx.MockTransport(handler),
    )

    assert result == f"data:image/png;base64,{base64.b64encode(b'png').decode()}"
    assert requested_urls == ["https://images.test/start", "https://images.test/final.png"]
    assert resolver_calls == [("images.test", 443), ("images.test", 443)]


async def test_redirect_count_is_bounded(monkeypatch):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "images.test")
    _set_resolver(monkeypatch, {"images.test": ("93.184.216.34",)})
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(302, headers={"location": "/again"})

    with pytest.raises(image_urls.ImageURLFetchError, match="exceeded 5 redirects"):
        await image_urls.fetch_image_as_data_url(
            "https://images.test/start",
            transport=httpx.MockTransport(handler),
        )

    assert requests == image_urls.MAX_REDIRECTS + 1


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/v1/chat",
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image_url",
                                "image_url": {"url": "http://127.0.0.1/internal"},
                            }
                        ],
                    }
                ]
            },
        ),
        ("/v1/vision", {"prompt": "describe", "image": "http://127.0.0.1/internal"}),
    ],
)
def test_image_endpoints_reject_loopback_before_provider_call(app_client, monkeypatch, path, payload):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWED_HOSTS", "127.0.0.1")
    response = app_client.post(path, json=payload)

    assert response.status_code == 400
    assert "non-public address '127.0.0.1'" in response.json()["detail"]
