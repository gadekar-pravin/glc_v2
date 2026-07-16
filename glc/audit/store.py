"""Database-enforced append-only, hash-chained SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Schema v2 rejects UPDATE and DELETE statements with SQLite
triggers and links every immutable row to the SHA-256 hash of its predecessor.

Each append commits immediately so writes survive a hard kill. Startup fails
closed if the schema, append-only triggers, or hash chain is not intact.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))

SCHEMA_VERSION = 2
GENESIS_HASH = "0" * 64
_CHAIN_DOMAIN = "glc-audit-v2"
_TRIGGER_NAMES = {"audit_log_no_update", "audit_log_no_delete"}
_V1_COLUMNS = (
    "id",
    "ts",
    "session_id",
    "channel",
    "channel_user_id",
    "trust_level",
    "event_type",
    "tool",
    "policy_verdict",
    "params_json",
    "result_json",
)
_V2_COLUMNS = (*_V1_COLUMNS, "prev_hash", "entry_hash")
_HASHED_FIELDS = _V1_COLUMNS

_MIGRATION_TABLE_SQL = """
CREATE TABLE audit_log_v2 (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT,
    prev_hash       TEXT    NOT NULL
                            CHECK(length(prev_hash) = 64
                                  AND prev_hash NOT GLOB '*[^0-9a-f]*'),
    entry_hash      TEXT    NOT NULL
                            CHECK(length(entry_hash) = 64
                                  AND entry_hash NOT GLOB '*[^0-9a-f]*')
)
"""

_V2_OBJECT_STATEMENTS = (
    "CREATE INDEX idx_audit_ts ON audit_log(ts DESC)",
    "CREATE INDEX idx_audit_session ON audit_log(session_id, ts DESC)",
    "CREATE INDEX idx_audit_channel ON audit_log(channel, ts DESC)",
    """CREATE TRIGGER audit_log_no_update
       BEFORE UPDATE ON audit_log
       BEGIN
           SELECT RAISE(ABORT, 'audit_log is append-only');
       END""",
    """CREATE TRIGGER audit_log_no_delete
       BEFORE DELETE ON audit_log
       BEGIN
           SELECT RAISE(ABORT, 'audit_log is append-only');
       END""",
)


class AuditIntegrityError(RuntimeError):
    """The audit schema or hash chain cannot be trusted."""


def _resolve_path() -> str:
    """Resolve at call time so tests that swap the environment see it."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _table_exists(c: sqlite3.Connection, table: str) -> bool:
    row = c.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _column_names(c: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row["name"] for row in c.execute(f"PRAGMA table_info({table})").fetchall())


def _schema_versions(c: sqlite3.Connection) -> list[int]:
    if not _table_exists(c, "audit_schema"):
        raise AuditIntegrityError("audit_schema is missing")
    try:
        return [int(row["version"]) for row in c.execute("SELECT version FROM audit_schema").fetchall()]
    except (IndexError, KeyError, TypeError, ValueError, sqlite3.DatabaseError) as exc:
        raise AuditIntegrityError("audit_schema is malformed") from exc


def _trigger_names(c: sqlite3.Connection) -> set[str]:
    return {
        str(row["name"])
        for row in c.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'"
        ).fetchall()
    }


def _canonical_hash(row: Mapping[str, Any], prev_hash: str) -> str:
    payload = [_CHAIN_DOMAIN, *(row[field] for field in _HASHED_FIELDS), prev_hash]
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verify_chain_conn(c: sqlite3.Connection) -> bool:
    expected_prev = GENESIS_HASH
    try:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    except sqlite3.DatabaseError:
        return False

    try:
        for row in rows:
            if row["prev_hash"] != expected_prev:
                return False
            if row["entry_hash"] != _canonical_hash(row, expected_prev):
                return False
            expected_prev = row["entry_hash"]
    except (IndexError, KeyError, TypeError, ValueError):
        return False
    return True


def _validate_v2(c: sqlite3.Connection) -> None:
    if _column_names(c, "audit_log") != _V2_COLUMNS:
        raise AuditIntegrityError("audit_log schema does not match version 2")
    versions = _schema_versions(c)
    if not versions or max(versions) != SCHEMA_VERSION or any(v < 1 or v > SCHEMA_VERSION for v in versions):
        raise AuditIntegrityError("unsupported audit schema version")
    if _trigger_names(c) != _TRIGGER_NAMES:
        raise AuditIntegrityError("append-only audit triggers are missing or unexpected")
    if not _verify_chain_conn(c):
        raise AuditIntegrityError("audit hash chain verification failed")


def _migrate_v1_to_v2(c: sqlite3.Connection) -> None:
    if _column_names(c, "audit_log") != _V1_COLUMNS:
        raise AuditIntegrityError("audit_log schema does not match version 1")

    c.execute("BEGIN IMMEDIATE")
    try:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        sequence_row = c.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_log'").fetchone()
        old_high_water = int(sequence_row["seq"]) if sequence_row is not None else 0

        c.execute(_MIGRATION_TABLE_SQL)
        prev_hash = GENESIS_HASH
        for row in rows:
            row_values = dict(row)
            entry_hash = _canonical_hash(row_values, prev_hash)
            c.execute(
                """INSERT INTO audit_log_v2
                   (id, ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json,
                    prev_hash, entry_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                tuple(row_values[field] for field in _V1_COLUMNS) + (prev_hash, entry_hash),
            )
            prev_hash = entry_hash

        c.execute("DROP TABLE audit_log")
        c.execute("ALTER TABLE audit_log_v2 RENAME TO audit_log")
        migrated_max = max((int(row["id"]) for row in rows), default=0)
        high_water = max(old_high_water, migrated_max)
        c.execute("DELETE FROM sqlite_sequence WHERE name IN ('audit_log', 'audit_log_v2')")
        c.execute("INSERT INTO sqlite_sequence(name, seq) VALUES ('audit_log', ?)", (high_water,))
        for statement in _V2_OBJECT_STATEMENTS:
            c.execute(statement)
        c.execute(
            "INSERT INTO audit_schema(version, applied_at) VALUES (?, ?)",
            (SCHEMA_VERSION, time.time()),
        )
        if not _verify_chain_conn(c):
            raise AuditIntegrityError("migrated audit hash chain verification failed")
        c.execute("COMMIT")
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise


def init_store() -> None:
    """Create, migrate, and verify the audit store before it is used."""
    with _conn() as c:
        has_log = _table_exists(c, "audit_log")
        has_schema = _table_exists(c, "audit_schema")
        if not has_log and not has_schema:
            c.executescript(_SCHEMA_PATH.read_text())
        elif not has_log or not has_schema:
            raise AuditIntegrityError("audit database is only partially initialized")
        else:
            versions = _schema_versions(c)
            if not versions or any(v < 1 or v > SCHEMA_VERSION for v in versions):
                raise AuditIntegrityError("unsupported audit schema version")
            if max(versions) == 1:
                _migrate_v1_to_v2(c)

        _validate_v2(c)


def verify_chain() -> bool:
    """Return whether schema v2, its triggers, and the complete chain are intact."""
    try:
        with _conn() as c:
            _validate_v2(c)
        return True
    except (AuditIntegrityError, sqlite3.DatabaseError, IndexError, KeyError, TypeError, ValueError):
        return False


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Database-enforced write-once store with a single append method."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        row_values: dict[str, Any] = {
            "ts": time.time(),
            "session_id": session_id,
            "channel": channel,
            "channel_user_id": channel_user_id,
            "trust_level": trust_level,
            "event_type": event_type,
            "tool": tool,
            "policy_verdict": policy_verdict,
            "params_json": _jsonify(params),
            "result_json": _jsonify(result),
        }
        with _conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                tail = c.execute("SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                sequence_row = c.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_log'").fetchone()
                high_water = int(sequence_row["seq"]) if sequence_row is not None else 0
                if tail is not None:
                    high_water = max(high_water, int(tail["id"]))
                row_values["id"] = high_water + 1
                prev_hash = str(tail["entry_hash"]) if tail is not None else GENESIS_HASH
                entry_hash = _canonical_hash(row_values, prev_hash)
                c.execute(
                    """INSERT INTO audit_log
                       (id, ts, session_id, channel, channel_user_id, trust_level,
                        event_type, tool, policy_verdict, params_json, result_json,
                        prev_hash, entry_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    tuple(row_values[field] for field in _V1_COLUMNS) + (prev_hash, entry_hash),
                )
                c.execute("COMMIT")
                return int(row_values["id"])
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where: list[str] = []
    args: list[str | int] = []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        versions = _schema_versions(c)
        return max(versions, default=0)
