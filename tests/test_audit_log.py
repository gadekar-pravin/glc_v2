"""Append-only audit log correctness, migration, and tamper detection."""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from glc.audit import store
from glc.audit.store import (
    GENESIS_HASH,
    AuditIntegrityError,
    AuditStore,
    append,
    init_store,
    query,
    schema_version,
    verify_chain,
)


def _db_path() -> str:
    return os.environ["GLC_AUDIT_DB"]


@contextmanager
def _raw_connection():
    connection = sqlite3.connect(_db_path())
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _create_v1_database() -> None:
    with _raw_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                session_id TEXT,
                channel TEXT NOT NULL,
                channel_user_id TEXT NOT NULL,
                trust_level TEXT NOT NULL,
                event_type TEXT NOT NULL,
                tool TEXT,
                policy_verdict TEXT,
                params_json TEXT,
                result_json TEXT
            );
            CREATE INDEX idx_audit_ts ON audit_log(ts DESC);
            CREATE INDEX idx_audit_session ON audit_log(session_id, ts DESC);
            CREATE INDEX idx_audit_channel ON audit_log(channel, ts DESC);
            CREATE TABLE audit_schema (
                version INTEGER PRIMARY KEY,
                applied_at REAL NOT NULL
            );
            INSERT INTO audit_schema(version, applied_at) VALUES (1, 1000);
            """
        )
        connection.execute(
            """INSERT INTO audit_log
               (id, ts, session_id, channel, channel_user_id, trust_level,
                event_type, tool, policy_verdict, params_json, result_json)
               VALUES (2, 1001, 'session-old', 'discord', 'user-2',
                       'owner_paired', 'tool_dispatch', 'llm.chat', 'allow',
                       '{"prompt":"hello"}', '{"ok":true}')"""
        )
        connection.execute(
            """INSERT INTO audit_log
               (id, ts, session_id, channel, channel_user_id, trust_level,
                event_type, params_json)
               VALUES (5, 1002, 'session-new', 'telegram', 'user-5',
                       'user_paired', 'inbound_message', '{"text":"hi"}')"""
        )
        # Preserve proof that AUTOINCREMENT once reached 9 even though that row
        # no longer exists in the legacy database.
        connection.execute(
            """INSERT INTO audit_log
               (id, ts, channel, channel_user_id, trust_level, event_type)
               VALUES (9, 1003, 'legacy', 'deleted', 'untrusted', 'legacy')"""
        )
        connection.execute("DELETE FROM audit_log WHERE id=9")


def test_init_then_append_creates_hash_chain():
    init_store()
    first_id = append(
        channel="telegram",
        channel_user_id="42",
        trust_level="owner_paired",
        event_type="inbound_message",
        session_id="s1",
        params={"text": "hi"},
    )
    second_id = append(
        channel="telegram",
        channel_user_id="42",
        trust_level="owner_paired",
        event_type="tool_dispatch",
        session_id="s1",
        result={"ok": True},
    )

    rows = list(reversed(query(limit=5)))
    assert [row["id"] for row in rows] == [first_id, second_id]
    assert rows[0]["prev_hash"] == GENESIS_HASH
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert all(len(row["entry_hash"]) == 64 for row in rows)
    assert verify_chain()


def test_write_survives_restart():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="boot")
    store._singleton = None  # simulate process restart
    init_store()
    assert len(query(limit=10)) == 1
    assert verify_chain()


def test_store_exposes_no_update_or_delete():
    public = [name for name in dir(AuditStore()) if not name.startswith("_")]
    assert "append" in public
    assert not any(name in public for name in ("update", "delete", "modify"))


def test_schema_version_is_two():
    init_store()
    assert schema_version() == 2


def test_query_filters_and_returns_chain_fields():
    init_store()
    append(
        channel="discord", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-A"
    )
    append(
        channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-B"
    )
    rows = query(session_id="s-A")
    assert len(rows) == 1
    assert rows[0]["channel"] == "discord"
    assert {"prev_hash", "entry_hash"}.issubset(rows[0])
    assert [row["channel"] for row in query(channel="telegram")] == ["telegram"]


def test_jsonifies_complex_params():
    init_store()
    append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="x",
        params={"nested": {"k": [1, 2, 3]}},
    )
    assert "nested" in query(limit=1)[0]["params_json"]


def test_exact_delete_attack_is_blocked_and_preserves_history():
    init_store()
    append(channel="probe", channel_user_id="attacker", trust_level="untrusted", event_type="before_delete")

    with _raw_connection() as connection:
        before = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM audit_log")
        after = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

    assert before == after == 1
    assert verify_chain()


def test_direct_update_is_blocked():
    init_store()
    row_id = append(channel="x", channel_user_id="1", trust_level="untrusted", event_type="original")
    with _raw_connection() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE audit_log SET event_type='rewritten' WHERE id=?", (row_id,))
    assert query(limit=1)[0]["event_type"] == "original"
    assert verify_chain()


def test_v1_migration_preserves_rows_payloads_and_sequence_high_water():
    _create_v1_database()

    init_store()

    rows = list(reversed(query(limit=10)))
    assert [row["id"] for row in rows] == [2, 5]
    assert rows[0]["params_json"] == '{"prompt":"hello"}'
    assert rows[0]["result_json"] == '{"ok":true}'
    assert rows[1]["session_id"] == "session-new"
    assert schema_version() == 2
    assert verify_chain()
    assert (
        append(channel="post", channel_user_id="10", trust_level="owner_paired", event_type="migrated") == 10
    )


def test_concurrent_appends_have_unique_ids_and_valid_chain():
    init_store()

    def write(index: int) -> int:
        return append(
            channel="concurrent",
            channel_user_id=str(index),
            trust_level="owner_paired",
            event_type="append",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        ids = list(executor.map(write, range(24)))

    assert sorted(ids) == list(range(1, 25))
    assert len(query(limit=100)) == 24
    assert verify_chain()


def test_modified_content_fails_chain_verification_and_startup():
    init_store()
    row_id = append(channel="x", channel_user_id="1", trust_level="untrusted", event_type="original")
    with _raw_connection() as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='audit_log_no_update'"
        ).fetchone()["sql"]
        connection.execute("DROP TRIGGER audit_log_no_update")
        connection.execute("UPDATE audit_log SET event_type='rewritten' WHERE id=?", (row_id,))
        connection.execute(trigger_sql)

    assert not verify_chain()
    with pytest.raises(AuditIntegrityError, match="hash chain"):
        init_store()


def test_broken_previous_link_fails_closed():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="untrusted", event_type="first")
    second_id = append(channel="x", channel_user_id="1", trust_level="untrusted", event_type="second")
    with _raw_connection() as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='audit_log_no_update'"
        ).fetchone()["sql"]
        connection.execute("DROP TRIGGER audit_log_no_update")
        connection.execute("UPDATE audit_log SET prev_hash=? WHERE id=?", (GENESIS_HASH, second_id))
        connection.execute(trigger_sql)

    assert not verify_chain()
    with pytest.raises(AuditIntegrityError, match="hash chain"):
        init_store()


def test_missing_trigger_fails_closed():
    init_store()
    with _raw_connection() as connection:
        connection.execute("DROP TRIGGER audit_log_no_delete")

    assert not verify_chain()
    with pytest.raises(AuditIntegrityError, match="triggers"):
        init_store()


def test_same_named_noop_trigger_fails_closed():
    init_store()
    with _raw_connection() as connection:
        connection.execute("DROP TRIGGER audit_log_no_delete")
        connection.execute(
            """CREATE TRIGGER audit_log_no_delete
               BEFORE DELETE ON audit_log
               BEGIN
                   SELECT 1;
               END"""
        )

    assert not verify_chain()
    with pytest.raises(AuditIntegrityError, match="triggers"):
        init_store()


def test_unsupported_schema_version_fails_closed():
    init_store()
    with _raw_connection() as connection:
        connection.execute("INSERT INTO audit_schema(version, applied_at) VALUES (3, 1000)")

    assert not verify_chain()
    with pytest.raises(AuditIntegrityError, match="unsupported"):
        init_store()


def test_malformed_schema_version_table_fails_closed():
    init_store()
    with _raw_connection() as connection:
        connection.execute("DROP TABLE audit_schema")
        connection.execute("CREATE TABLE audit_schema(not_version TEXT)")
        connection.execute("INSERT INTO audit_schema(not_version) VALUES ('two')")

    assert not verify_chain()
    with pytest.raises(AuditIntegrityError, match="malformed"):
        init_store()
