"""Leak 10 regression: only the gateway-owned signed writer can book cost."""

from __future__ import annotations

import sqlite3
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from glc import db
from glc.ledger import LedgerIntegrityError, SignedLedgerWriter
from glc.routing import Router

TEST_KEY = b"test-ledger-signing-key-at-least-32-bytes"


@pytest.fixture
def ledger(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "gateway.sqlite"))
    db.init()
    writer = SignedLedgerWriter(TEST_KEY)
    writer.init()
    return writer


def test_exact_unsigned_log_call_exploit_is_removed(ledger):
    assert not hasattr(db, "log_call")
    with pytest.raises(AttributeError):
        db.log_call(  # type: ignore[attr-defined]
            provider="gemini",
            model="x",
            input_tokens=999_999_999,
            agent="victim",
        )
    assert ledger.recent() == []


@pytest.mark.parametrize("value", [999_999_999, -1, "100"])
def test_token_counts_are_strict_and_bounded(ledger, value):
    with pytest.raises(ValueError, match="invalid ledger entry"):
        ledger.log_call(provider="gemini", model="x", input_tokens=value)
    assert ledger.recent() == []


def test_valid_signed_entry_preserves_v9_read_shapes(ledger):
    ledger.log_call(
        provider="gemini",
        model="gemini-test",
        input_tokens=12,
        output_tokens=3,
        latency_ms=7,
        agent="trusted-agent",
    )
    row = ledger.recent()[0]
    assert "signature" not in row
    assert "event_id" not in row
    assert row["input_tokens"] == 12
    assert ledger.by_agent()["trusted-agent"][0]["in_tok"] == 12
    assert ledger.aggregate(call_role="worker")["gemini"]["calls"] == 1
    with db.conn() as c:
        stored = c.execute("SELECT signature, event_id FROM calls").fetchone()
    assert len(stored["signature"]) == 64
    assert len(stored["event_id"]) == 32


def test_unsigned_insert_and_signed_replay_are_rejected(ledger):
    ledger.log_call(provider="gemini", model="x")
    with db.conn() as c:
        row = dict(c.execute("SELECT * FROM calls").fetchone())
        columns = [column for column in row if column != "id"]
        replay_values = [row[column] for column in columns]
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                f"INSERT INTO calls ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                replay_values,
            )
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                """INSERT INTO calls
                   (schema_version, event_id, ts, provider, model, status)
                   VALUES (2, ?, ?, 'gemini', 'x', 'ok')""",
                ("f" * 32, time.time()),
            )
    assert len(ledger.recent()) == 1


def test_tampering_is_blocked_and_invalid_signature_fails_closed(ledger):
    ledger.log_call(provider="gemini", model="x", input_tokens=5)
    with db.conn() as c:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            c.execute("UPDATE calls SET input_tokens=999 WHERE provider='gemini'")

    with db.conn() as c:
        c.execute("DROP TRIGGER calls_no_update")
        c.execute("UPDATE calls SET input_tokens=999 WHERE provider='gemini'")
        c.execute(
            """CREATE TRIGGER calls_no_update BEFORE UPDATE ON calls BEGIN
                   SELECT RAISE(ABORT, 'calls ledger is append-only');
               END"""
        )
    with pytest.raises(LedgerIntegrityError, match="invalid signature"):
        ledger.recent()
    assert ledger.integrity_ok() is False


def test_non_boolean_reasoning_value_fails_before_canonicalization(ledger):
    ledger.log_call(provider="gemini", model="x", reasoning_applied=True)
    with db.conn() as c:
        c.execute("DROP TRIGGER calls_no_update")
        c.execute("UPDATE calls SET reasoning_applied=2 WHERE provider='gemini'")
        c.execute(
            """CREATE TRIGGER calls_no_update BEFORE UPDATE ON calls BEGIN
                   SELECT RAISE(ABORT, 'calls ledger is append-only');
               END"""
        )

    with pytest.raises(LedgerIntegrityError, match="invalid reasoning_applied"):
        ledger.recent()
    assert ledger.integrity_ok() is False


def test_unsigned_legacy_rows_are_quarantined(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "legacy.sqlite"))
    with db.conn() as c:
        c.execute(
            """CREATE TABLE calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER DEFAULT 0,
                agent TEXT
            )"""
        )
        c.execute(
            "INSERT INTO calls (ts, provider, model, input_tokens, agent) VALUES (?, 'gemini', 'x', 999999999, 'victim')",
            (time.time(),),
        )
    db.init()
    writer = SignedLedgerWriter(TEST_KEY)
    writer.init()
    assert writer.recent() == []
    assert writer.by_agent() == {}
    with db.conn() as c:
        legacy = c.execute("SELECT input_tokens, agent FROM calls_legacy_unsigned").fetchone()
        active_count = c.execute("SELECT COUNT(*) AS n FROM calls").fetchone()["n"]
    assert dict(legacy) == {"input_tokens": 999_999_999, "agent": "victim"}
    assert active_count == 0


def test_production_requires_a_dedicated_strong_key(monkeypatch):
    monkeypatch.delenv("GLC_LEDGER_SIGNING_KEY", raising=False)
    with pytest.raises(RuntimeError, match="required in production"):
        SignedLedgerWriter.from_environment(production=True)
    monkeypatch.setenv("GLC_LEDGER_SIGNING_KEY", "short")
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        SignedLedgerWriter.from_environment(production=True)


def test_trusted_local_client_keeps_agent_attribution(app_client):
    provider = SimpleNamespace(
        name="gemini",
        model="gemini-test-model",
        capabilities={},
        chat=AsyncMock(
            return_value={
                "text": "ok",
                "tool_calls": [],
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "stop_reason": "end_turn",
                "model": "gemini-test-model",
                "tool_call_dialect": "none",
                "reasoning_applied": False,
            }
        ),
    )
    app_client.app.state.router = Router({"gemini": provider}, ["gemini"])
    response = app_client.post(
        "/v1/chat",
        json={"prompt": "trusted", "provider": "gemini", "agent": "trusted-agent"},
    )
    assert response.status_code == 200
    assert app_client.app.state.ledger.recent()[0]["agent"] == "trusted-agent"
