"""Single-use credential issuance, route scope, and replay regression tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from glc import db
from glc.creds.issuer import issue_token
from glc.creds.verify import CredentialError, verify_and_consume
from glc.isolation.manifest import get_slot
from glc.main import create_app
from glc.routing import Router


@pytest.fixture
def credential_client(monkeypatch, tmp_path):
    import glc.security.allowlists as allowlists

    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "gateway.sqlite"))
    monkeypatch.setattr(
        allowlists,
        "load_channels",
        lambda: {"channels": {"telegram": {"enabled": True, "allowed_senders": []}}},
    )
    monkeypatch.setenv("GLC_CREDS_SIGNING_KEY", "test-signing-key-not-a-provider-key")
    monkeypatch.setenv("GLC_SLOT_IDENTITY_TELEGRAM", "telegram-identity")
    monkeypatch.setenv("GLC_SLOT_IDENTITY_LOCAL_MIC", "local-mic-identity")
    with TestClient(create_app(production=True)) as client:
        yield client


def _issue(client: TestClient, *, identity: str = "telegram-identity", tool: str = "llm.chat", **body):
    return client.post(
        "/v1/creds/issue",
        json={"tool": tool, **body},
        headers={"Authorization": f"Bearer {identity}"},
    )


def test_issue_derives_slot_and_enforces_manifest_scope(credential_client):
    missing = credential_client.post("/v1/creds/issue", json={"tool": "llm.chat"})
    assert missing.status_code == 401
    assert _issue(credential_client, identity="wrong").status_code == 401
    non_ascii = credential_client.post(
        "/v1/creds/issue",
        json={"tool": "llm.chat"},
        headers=[(b"authorization", b"Bearer \xe2\x98\x83")],
    )
    assert non_ascii.status_code == 401

    issued = _issue(credential_client)
    assert issued.status_code == 200
    assert issued.json()["token_type"] == "bearer"
    assert issued.json()["scope"] == "llm.chat"
    assert "adapter" not in issued.json()

    disallowed = _issue(credential_client, tool="tts.synthesize")
    assert disallowed.status_code == 403


def test_correct_scope_consumes_once_and_replay_fails(credential_client):
    token = _issue(credential_client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    first = credential_client.post(
        "/v1/chat",
        json={"prompt": "hello", "provider": "gemini"},
        headers=headers,
    )
    assert first.status_code not in {401, 403}
    replay = credential_client.post(
        "/v1/chat",
        json={"prompt": "again", "provider": "gemini"},
        headers=headers,
    )
    assert replay.status_code == 401
    assert "already used" in replay.json()["detail"]


def test_slot_cannot_forge_cost_ledger_agent(credential_client):
    provider = SimpleNamespace(
        name="gemini",
        model="gemini-test-model",
        capabilities={},
        chat=AsyncMock(
            return_value={
                "text": "ok",
                "tool_calls": [],
                "input_tokens": 3,
                "output_tokens": 2,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "stop_reason": "end_turn",
                "model": "gemini-test-model",
                "tool_call_dialect": "none",
                "reasoning_applied": False,
            }
        ),
    )
    credential_client.app.state.router = Router({"gemini": provider}, ["gemini"])
    token = _issue(credential_client).json()["access_token"]
    response = credential_client.post(
        "/v1/chat",
        json={"prompt": "charge somebody else", "provider": "gemini", "agent": "victim"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    rows = credential_client.app.state.ledger.recent(limit=10)
    assert rows[0]["agent"] == "telegram"
    assert all(row["agent"] != "victim" for row in rows)


def test_wrong_scope_does_not_consume_intended_grant(credential_client):
    token = _issue(credential_client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    denied = credential_client.post("/v1/speak", json={"text": "no"}, headers=headers)
    assert denied.status_code == 403

    intended = credential_client.post(
        "/v1/chat",
        json={"prompt": "yes", "provider": "gemini"},
        headers=headers,
    )
    assert intended.status_code not in {401, 403}


def test_model_bound_grant_requires_the_same_explicit_model(credential_client):
    token = _issue(credential_client, model="gemini-2.5-flash").json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    mismatch = credential_client.post(
        "/v1/chat",
        json={"prompt": "missing model", "provider": "gemini"},
        headers=headers,
    )
    assert mismatch.status_code == 403

    matched = credential_client.post(
        "/v1/chat",
        json={"prompt": "matching model", "provider": "gemini", "model": "gemini-2.5-flash"},
        headers=headers,
    )
    assert matched.status_code not in {401, 403}


def test_install_token_client_remains_compatible(credential_client):
    from glc.config import get_or_create_install_token

    response = credential_client.post(
        "/v1/chat",
        json={"prompt": "trusted", "provider": "gemini"},
        headers={"Authorization": f"Bearer {get_or_create_install_token()}"},
    )
    assert response.status_code not in {401, 403}


def test_slot_identity_authenticates_only_its_matching_websocket(credential_client):
    headers = {"Authorization": "Bearer telegram-identity"}
    with credential_client.websocket_connect("/v1/channels/telegram", headers=headers) as websocket:
        websocket.send_text("not-json")
        assert "invalid envelope" in websocket.receive_text()

    with pytest.raises(WebSocketDisconnect) as rejected:
        with credential_client.websocket_connect("/v1/channels/discord", headers=headers) as websocket:
            websocket.receive_text()
    assert rejected.value.code == 1008


def _ingress(*, user_id: str, channel: str = "telegram", trust_level: str | None = None) -> dict:
    payload = {
        "channel": channel,
        "channel_user_id": user_id,
        "user_handle": user_id,
        "text": "boundary probe",
        "arrived_at": datetime.now(UTC).isoformat(),
        "metadata": {"is_public_channel": False, "was_mentioned": False},
    }
    if trust_level is not None:
        payload["trust_level"] = trust_level
    return payload


def _pair_owner(client: TestClient, *, user_id: str, channel: str = "telegram") -> None:
    from glc.config import get_or_create_install_token

    headers = {"Authorization": f"Bearer {get_or_create_install_token()}"}
    issued = client.post(
        "/v1/control/pair",
        headers=headers,
        json={
            "channel": channel,
            "channel_user_id": user_id,
            "user_handle": "owner",
            "trust_level": "owner_paired",
        },
    )
    assert issued.status_code == 200
    confirmed = client.post(
        "/v1/control/pair/confirm",
        headers=headers,
        json={"code": issued.json()["code"]},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["trust_level"] == "owner_paired"


def test_gateway_ignores_forged_owner_claim(credential_client):
    headers = {"Authorization": "Bearer telegram-identity"}
    with credential_client.websocket_connect("/v1/channels/telegram", headers=headers) as websocket:
        websocket.send_json(_ingress(user_id="attacker-id", trust_level="owner_paired"))
        response = websocket.receive_json()
    assert "dropped" in response["error"]


def test_gateway_uses_pairing_db_even_when_adapter_claims_untrusted(credential_client):
    _pair_owner(credential_client, user_id="real-owner")
    headers = {"Authorization": "Bearer telegram-identity"}
    with credential_client.websocket_connect("/v1/channels/telegram", headers=headers) as websocket:
        websocket.send_json(_ingress(user_id="real-owner", trust_level="untrusted"))
        response = websocket.receive_json()
    assert "error" not in response, response
    assert response["channel"] == "telegram"
    assert response["channel_user_id"] == "real-owner"
    assert response["text"] == "[glc echo] boundary probe"


def test_gateway_rejects_claimed_channel_that_differs_from_route(credential_client):
    headers = {"Authorization": "Bearer telegram-identity"}
    with credential_client.websocket_connect("/v1/channels/telegram", headers=headers) as websocket:
        websocket.send_json(_ingress(user_id="route-owner", channel="discord", trust_level="owner_paired"))
        with pytest.raises(WebSocketDisconnect) as rejected:
            websocket.receive_json()
    assert rejected.value.code == 1008


def test_gateway_refreshes_pairings_without_websocket_reconnect(credential_client):
    headers = {"Authorization": "Bearer telegram-identity"}
    with credential_client.websocket_connect("/v1/channels/telegram", headers=headers) as websocket:
        websocket.send_json(_ingress(user_id="late-owner", trust_level="owner_paired"))
        assert "dropped" in websocket.receive_json()["error"]

        _pair_owner(credential_client, user_id="late-owner")

        websocket.send_json(_ingress(user_id="late-owner"))
        response = websocket.receive_json()
        assert "error" not in response, response
        assert response["text"] == "[glc echo] boundary probe"


def test_production_gateway_never_instantiates_webhook_adapters(credential_client):
    from glc.config import get_or_create_install_token

    response = credential_client.post(
        "/v1/channels/telegram/webhook",
        content=b"{}",
        headers={"Authorization": f"Bearer {get_or_create_install_token()}"},
    )
    assert response.status_code == 404
    assert "isolated slot containers" in response.json()["detail"]


@pytest.mark.parametrize(
    ("tool", "path", "payload"),
    [
        ("llm.chat", "/v1/chat", {"prompt": "x", "provider": "gemini"}),
        ("llm.chat.batch", "/v1/chat/batch", {"calls": [], "max_concurrency": 1}),
        ("llm.vision", "/v1/vision", {"prompt": "x", "image": "data:image/png;base64,AA=="}),
        ("llm.embed", "/v1/embed", {"text": "x"}),
        ("stt.transcribe", "/v1/transcribe", {"audio_b64": "", "mime": "audio/wav"}),
        ("tts.synthesize", "/v1/speak", {"text": "x", "prefer": "quality"}),
    ],
)
def test_all_tool_routes_accept_their_exact_scope(credential_client, tool, path, payload):
    slot = replace(get_slot("telegram"), allowed_tools=(tool,))
    issued = issue_token(slot=slot, tool=tool)
    response = credential_client.post(
        path,
        json=payload,
        headers={"Authorization": f"Bearer {issued.access_token}"},
    )
    assert response.status_code not in {401, 403}


def test_atomic_consume_allows_only_one_concurrent_winner(credential_client):
    issued = issue_token(slot=get_slot("telegram"), tool="llm.chat")
    authorization = f"Bearer {issued.access_token}"

    def attempt() -> bool:
        try:
            verify_and_consume(authorization, expected_tool="llm.chat")
            return True
        except CredentialError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: attempt(), range(2))) == [False, True]


def test_forged_and_expired_tokens_fail_closed(credential_client, monkeypatch):
    issued = issue_token(slot=get_slot("telegram"), tool="llm.chat")
    monkeypatch.setenv("GLC_CREDS_SIGNING_KEY", "different-signing-key-at-least-32-bytes")
    with pytest.raises(CredentialError, match="invalid"):
        verify_and_consume(f"Bearer {issued.access_token}", expected_tool="llm.chat")

    monkeypatch.setenv("GLC_CREDS_SIGNING_KEY", "test-signing-key-not-a-provider-key")
    expired = issue_token(
        slot=get_slot("telegram"),
        tool="llm.chat",
        now=1,
        ttl_seconds=1,
    )
    with pytest.raises(CredentialError, match="expired"):
        verify_and_consume(f"Bearer {expired.access_token}", expected_tool="llm.chat")
