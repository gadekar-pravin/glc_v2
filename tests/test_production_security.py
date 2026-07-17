"""Production gateway perimeter: route secrecy and bearer authentication."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from glc.config import get_or_create_install_token
from glc.main import create_app


@pytest.fixture
def production_client(monkeypatch):
    monkeypatch.setenv("GLC_INSTALL_TOKEN", "production-test-install-token")
    with TestClient(create_app(production=True)) as client:
        yield client


@pytest.fixture
def production_auth(production_client):
    return {"Authorization": f"Bearer {get_or_create_install_token()}"}


def test_healthz_requires_valid_bearer_token(production_client, production_auth):
    missing = production_client.get("/healthz")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"

    malformed = production_client.get("/healthz", headers={"Authorization": "Basic abc"})
    assert malformed.status_code == 401

    empty = production_client.get("/healthz", headers={"Authorization": "Bearer "})
    assert empty.status_code == 401

    incorrect = production_client.get("/healthz", headers={"Authorization": "Bearer incorrect"})
    assert incorrect.status_code == 403

    non_ascii = production_client.get("/healthz", headers=[(b"authorization", b"Bearer \xe2\x98\x83")])
    assert non_ascii.status_code == 403

    authenticated = production_client.get("/healthz", headers=production_auth)
    assert authenticated.status_code == 200
    assert authenticated.json() == {"ok": True, "port": 8111}


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
def test_documentation_is_disabled_even_with_authentication(production_client, production_auth, path):
    unauthenticated = production_client.get(path)
    assert unauthenticated.status_code == 401
    assert "paths" not in unauthenticated.json()

    authenticated = production_client.get(path, headers=production_auth)
    assert authenticated.status_code == 404


def test_gateway_auth_covers_api_control_and_webhook_routes(production_client, production_auth):
    assert production_client.get("/").status_code == 401
    assert production_client.get("/v1/providers").status_code == 401
    assert production_client.post("/v1/chat", json={"prompt": "hi"}).status_code == 401
    assert (
        production_client.post(
            "/v1/control/pair",
            json={"channel": "telegram", "channel_user_id": "1"},
        ).status_code
        == 401
    )
    assert production_client.post("/v1/channels/webhook/webhook", content=b"{}").status_code == 401

    assert production_client.get("/v1/providers", headers=production_auth).status_code == 200
    control = production_client.post(
        "/v1/control/pair",
        headers=production_auth,
        json={"channel": "telegram", "channel_user_id": "1"},
    )
    assert control.status_code == 200


@pytest.mark.parametrize(
    "path",
    ["/v1/chat", "/v1/chat/batch", "/v1/vision", "/v1/embed", "/v1/creds/issue"],
)
def test_scoped_routes_authenticate_before_body_validation(production_client, path):
    response = production_client.post(path, json={})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "field required" not in response.text.lower()


def test_production_index_does_not_advertise_docs(production_client, production_auth):
    response = production_client.get("/", headers=production_auth)
    assert response.status_code == 200
    assert "/docs" not in response.text


def test_websocket_still_requires_install_token(production_client):
    with pytest.raises(WebSocketDisconnect) as rejected:
        with production_client.websocket_connect("/v1/channels/webui") as websocket:
            websocket.receive_text()
    assert rejected.value.code == 1008

    token = get_or_create_install_token()
    with production_client.websocket_connect(f"/v1/channels/webui?token={token}") as websocket:
        websocket.send_text("not-json")
        assert "invalid envelope" in websocket.receive_text()
