"""C4 regression tests: upstream failures stay out of client responses."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from glc.providers import ProviderError
from glc.routing import Router

PUBLIC_UPSTREAM_ERROR = "upstream provider request failed"

RAW_UPSTREAM_ERROR = (
    "gemini HTTP 400: API_KEY_INVALID at "
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash"
)


@pytest.fixture(autouse=True)
def _bind_gateway_db_to_test_tmp(monkeypatch, tmp_path):
    """Handle suites that import glc.db before the shared env fixture runs."""
    from glc import db

    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "gateway.sqlite"))


def _provider(name: str, chat) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        model=f"{name}-test-model",
        capabilities={"vision": True},
        chat=chat,
    )


def _install_router(app_client, providers: list[SimpleNamespace]) -> None:
    by_name = {provider.name: provider for provider in providers}
    app_client.app.state.router = Router(by_name, list(by_name))


def _success(model: str = "nvidia-test-model") -> dict:
    return {
        "text": "ok",
        "tool_calls": [],
        "input_tokens": 1,
        "output_tokens": 1,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "stop_reason": "end_turn",
        "model": model,
        "tool_call_dialect": "none",
        "reasoning_applied": False,
    }


def _failing_provider(*, retryable: bool = False) -> SimpleNamespace:
    failure = ProviderError(RAW_UPSTREAM_ERROR, status=400, retryable=retryable)
    return _provider("gemini", AsyncMock(side_effect=failure))


def test_pinned_provider_error_is_generic_logged_and_absent_from_calls(app_client, install_auth, caplog):
    _install_router(app_client, [_failing_provider()])
    caplog.set_level(logging.ERROR, logger="glc.routes.chat")

    response = app_client.post(
        "/v1/chat",
        json={"prompt": "hi", "provider": "gemini", "model": "gemini-2.5-flash"},
    )

    assert response.status_code == 502
    assert response.json() == {"detail": PUBLIC_UPSTREAM_ERROR}
    assert RAW_UPSTREAM_ERROR not in response.text
    assert RAW_UPSTREAM_ERROR in caplog.text

    from glc import db

    db.log_call(
        provider="gemini",
        model="historical-model",
        status="error",
        error=RAW_UPSTREAM_ERROR,
    )
    calls = app_client.get("/v1/calls", headers=install_auth)
    assert calls.status_code == 200
    assert RAW_UPSTREAM_ERROR not in calls.text
    assert calls.json()[0]["error"] == PUBLIC_UPSTREAM_ERROR


def test_exhausted_failover_error_is_generic(app_client):
    _install_router(app_client, [_failing_provider(retryable=True)])

    response = app_client.post("/v1/chat", json={"prompt": "hi"})

    assert response.status_code == 503
    assert response.json() == {"detail": PUBLIC_UPSTREAM_ERROR}
    assert RAW_UPSTREAM_ERROR not in response.text


def test_successful_failover_sanitizes_attempted_failure(app_client):
    failed = _failing_provider(retryable=True)
    succeeded = _provider("nvidia", AsyncMock(return_value=_success()))
    _install_router(app_client, [failed, succeeded])

    response = app_client.post("/v1/chat", json={"prompt": "hi"})

    assert response.status_code == 200
    assert response.json()["attempted"] == [{"provider": "gemini", "reason": PUBLIC_UPSTREAM_ERROR}]
    assert RAW_UPSTREAM_ERROR not in response.text


class _StreamingFailureProvider:
    name = "gemini"
    model = "gemini-test-model"
    capabilities = {"vision": True}

    async def stream(self, *args, **kwargs):  # noqa: ARG002
        if False:  # pragma: no cover - makes this an async generator
            yield ""
        raise RuntimeError(RAW_UPSTREAM_ERROR)


def test_streaming_error_event_is_generic_and_logged(app_client, caplog):
    _install_router(app_client, [_StreamingFailureProvider()])
    caplog.set_level(logging.ERROR, logger="glc.routes.chat")

    response = app_client.post(
        "/v1/chat",
        json={"prompt": "hi", "provider": "gemini", "stream": True},
    )

    assert response.status_code == 200
    assert PUBLIC_UPSTREAM_ERROR in response.text
    assert RAW_UPSTREAM_ERROR not in response.text
    assert RAW_UPSTREAM_ERROR in caplog.text


def test_batch_error_is_generic(app_client):
    _install_router(app_client, [_failing_provider()])

    response = app_client.post(
        "/v1/chat/batch",
        json={"calls": [{"prompt": "hi", "provider": "gemini"}]},
    )

    assert response.status_code == 200
    assert response.json() == {"results": [{"error": PUBLIC_UPSTREAM_ERROR, "status_code": 502}]}
    assert RAW_UPSTREAM_ERROR not in response.text


def test_vision_error_is_generic(app_client):
    _install_router(app_client, [_failing_provider()])

    response = app_client.post(
        "/v1/vision",
        json={
            "image": "data:image/png;base64,AA==",
            "prompt": "describe",
            "provider": "gemini",
        },
    )

    assert response.status_code == 502
    assert response.json() == {"detail": PUBLIC_UPSTREAM_ERROR}
    assert RAW_UPSTREAM_ERROR not in response.text
