"""Signed, append-only cost ledger owned by the trusted gateway process."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from collections import defaultdict
from typing import Any

from pydantic import ValidationError

from glc import db
from glc.config import get_or_create_install_token
from glc.ledger.models import LedgerEntry

_UPDATE_TRIGGER = "calls_no_update"
_DELETE_TRIGGER = "calls_no_delete"
_ACTIVE_COLUMNS = {
    "id",
    "schema_version",
    "event_id",
    "signature",
    "ts",
    "provider",
    "model",
    "input_tokens",
    "output_tokens",
    "cache_create_tokens",
    "cache_read_tokens",
    "latency_ms",
    "status",
    "error",
    "prompt_chars",
    "response_chars",
    "override",
    "attempted",
    "tool_calls",
    "reasoning_applied",
    "tool_dialect",
    "call_role",
    "router_decision",
    "embed_dim",
    "agent",
    "session",
    "retries",
}


class LedgerIntegrityError(RuntimeError):
    """The authoritative ledger cannot be trusted or written safely."""


def _key_from_environment(*, production: bool) -> bytes:
    configured = os.getenv("GLC_LEDGER_SIGNING_KEY", "")
    if configured:
        raw = configured.encode("utf-8")
        if len(raw) < 32:
            raise RuntimeError("GLC_LEDGER_SIGNING_KEY must be at least 32 bytes")
        return raw
    if production:
        raise RuntimeError("GLC_LEDGER_SIGNING_KEY is required in production")
    token = get_or_create_install_token()
    return hashlib.sha256(f"glc-ledger-v2:{token}".encode()).digest()


def _canonical(entry: LedgerEntry) -> bytes:
    return json.dumps(
        entry.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _signature(entry: LedgerEntry, key: bytes) -> str:
    return hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()


class SignedLedgerWriter:
    """Validate, sign, persist, and read authoritative call records."""

    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("ledger signing key must be at least 32 bytes")
        self._key = key

    @classmethod
    def from_environment(cls, *, production: bool) -> SignedLedgerWriter:
        return cls(_key_from_environment(production=production))

    def init(self) -> None:
        with db.conn() as c:
            self._migrate_or_create(c)
        self.verify_integrity()

    @staticmethod
    def _migrate_or_create(c: sqlite3.Connection) -> None:
        existing = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='calls'").fetchone()
        if existing is not None:
            columns = {row["name"] for row in c.execute("PRAGMA table_info(calls)").fetchall()}
            if not {"schema_version", "event_id", "signature"}.issubset(columns):
                legacy = c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='calls_legacy_unsigned'"
                ).fetchone()
                if legacy is not None:
                    raise LedgerIntegrityError("both unsigned calls and quarantine tables exist")
                c.execute("ALTER TABLE calls RENAME TO calls_legacy_unsigned")
                for index in ("idx_ts", "idx_prov_ts", "idx_role_ts", "idx_agent_ts", "idx_session_ts"):
                    c.execute(f"DROP INDEX IF EXISTS {index}")

        c.execute(
            """CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schema_version INTEGER NOT NULL CHECK(schema_version = 2),
                event_id TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL CHECK(length(signature) = 64),
                ts REAL NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                cache_create_tokens INTEGER NOT NULL DEFAULT 0,
                cache_read_tokens INTEGER NOT NULL DEFAULT 0,
                latency_ms INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                error TEXT,
                prompt_chars INTEGER NOT NULL DEFAULT 0,
                response_chars INTEGER NOT NULL DEFAULT 0,
                override TEXT,
                attempted TEXT,
                tool_calls INTEGER NOT NULL DEFAULT 0,
                reasoning_applied INTEGER NOT NULL DEFAULT 0,
                tool_dialect TEXT,
                call_role TEXT NOT NULL DEFAULT 'worker',
                router_decision TEXT,
                embed_dim INTEGER,
                agent TEXT,
                session TEXT,
                retries INTEGER NOT NULL DEFAULT 0
            )"""
        )
        columns = {row["name"] for row in c.execute("PRAGMA table_info(calls)").fetchall()}
        if columns != _ACTIVE_COLUMNS:
            raise LedgerIntegrityError("unsupported calls ledger schema")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON calls(ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_prov_ts ON calls(provider, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_role_ts ON calls(call_role, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_ts ON calls(agent, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_session_ts ON calls(session, ts DESC)")
        c.execute(
            f"""CREATE TRIGGER IF NOT EXISTS {_UPDATE_TRIGGER}
                BEFORE UPDATE ON calls BEGIN
                    SELECT RAISE(ABORT, 'calls ledger is append-only');
                END"""
        )
        c.execute(
            f"""CREATE TRIGGER IF NOT EXISTS {_DELETE_TRIGGER}
                BEFORE DELETE ON calls BEGIN
                    SELECT RAISE(ABORT, 'calls ledger is append-only');
                END"""
        )

    def log_call(self, *, provider: str, model: str, **values: Any) -> None:
        try:
            entry = LedgerEntry(
                event_id=uuid.uuid4().hex,
                ts=float(time.time()),
                provider=provider,
                model=model,
                **values,
            )
        except ValidationError as exc:
            raise ValueError(f"invalid ledger entry: {exc}") from None
        signature = _signature(entry, self._key)
        payload = entry.model_dump()
        columns = list(payload)
        columns.insert(2, "signature")
        payload["signature"] = signature
        placeholders = ",".join("?" for _ in columns)
        try:
            with db.conn() as c:
                c.execute(
                    f"INSERT INTO calls ({','.join(columns)}) VALUES ({placeholders})",
                    tuple(payload[column] for column in columns),
                )
        except sqlite3.IntegrityError as exc:
            raise LedgerIntegrityError(f"signed ledger append failed: {exc}") from None

    def _verified_rows(self) -> list[dict[str, Any]]:
        with db.conn() as c:
            trigger_names = {
                row["name"]
                for row in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='calls'"
                ).fetchall()
            }
            if not {_UPDATE_TRIGGER, _DELETE_TRIGGER}.issubset(trigger_names):
                raise LedgerIntegrityError("calls ledger append-only triggers are missing")
            rows = [dict(row) for row in c.execute("SELECT * FROM calls ORDER BY ts DESC").fetchall()]

        verified: list[dict[str, Any]] = []
        for row in rows:
            signature = row.pop("signature", None)
            public_id = row.pop("id", None)
            row["reasoning_applied"] = bool(row["reasoning_applied"])
            try:
                entry = LedgerEntry.model_validate(row)
            except ValidationError as exc:
                raise LedgerIntegrityError(f"invalid signed ledger row: {exc}") from None
            expected = _signature(entry, self._key)
            if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
                raise LedgerIntegrityError(f"invalid signature for ledger event {entry.event_id}")
            public = entry.model_dump()
            public.pop("schema_version")
            public.pop("event_id")
            public["id"] = public_id
            public["reasoning_applied"] = 1 if public["reasoning_applied"] else 0
            verified.append(public)
        return verified

    def verify_integrity(self) -> None:
        self._verified_rows()

    def integrity_ok(self) -> bool:
        try:
            self.verify_integrity()
        except (LedgerIntegrityError, sqlite3.Error):
            return False
        return True

    def recent(
        self,
        *,
        limit: int = 100,
        provider: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._verified_rows()
        if provider:
            rows = [row for row in rows if row["provider"] == provider]
        if status:
            rows = [row for row in rows if row["status"] == status]
        return rows[: max(0, limit)]

    def by_agent(self, *, session: str | None = None, since: float | None = None) -> dict[str, list[dict]]:
        day_start = time.time() - (time.time() % 86400)
        cutoff = day_start if since is None else since
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for row in self._verified_rows():
            agent = row["agent"]
            if agent is None or row["ts"] < cutoff or (session and row["session"] != session):
                continue
            key = (agent, row["provider"])
            bucket = grouped.setdefault(
                key,
                {
                    "agent": agent,
                    "provider": row["provider"],
                    "calls": 0,
                    "in_tok": 0,
                    "out_tok": 0,
                    "total_latency_ms": 0,
                    "total_retries": 0,
                    "ok": 0,
                    "errors": 0,
                },
            )
            bucket["calls"] += 1
            bucket["in_tok"] += row["input_tokens"]
            bucket["out_tok"] += row["output_tokens"]
            bucket["total_latency_ms"] += row["latency_ms"]
            bucket["total_retries"] += row["retries"]
            bucket["ok"] += int(row["status"] == "ok")
            bucket["errors"] += int(row["status"] == "error")
        out: defaultdict[str, list[dict]] = defaultdict(list)
        for (agent, _provider), bucket in grouped.items():
            out[agent].append(bucket)
        return dict(out)

    def aggregate(self, *, call_role: str | None = None) -> dict[str, dict[str, Any]]:
        day_start = time.time() - (time.time() % 86400)
        grouped: dict[str, dict[str, Any]] = {}
        latency: defaultdict[str, list[int]] = defaultdict(list)
        for row in self._verified_rows():
            role = row["call_role"]
            if row["ts"] < day_start:
                continue
            if call_role == "worker" and role != "worker":
                continue
            if call_role == "router" and not role.startswith("router"):
                continue
            if call_role not in {None, "worker", "router"} and role != call_role:
                continue
            provider = row["provider"]
            bucket = grouped.setdefault(
                provider,
                {
                    "provider": provider,
                    "calls": 0,
                    "ok_calls": 0,
                    "errors": 0,
                    "in_tok": 0,
                    "out_tok": 0,
                    "cache_reads": 0,
                    "cache_creates": 0,
                    "tool_calls": 0,
                    "avg_latency": 0.0,
                    "last_ts": 0.0,
                },
            )
            bucket["calls"] += 1
            bucket["ok_calls"] += int(row["status"] == "ok")
            bucket["errors"] += int(row["status"] == "error")
            bucket["in_tok"] += row["input_tokens"]
            bucket["out_tok"] += row["output_tokens"]
            bucket["cache_reads"] += row["cache_read_tokens"]
            bucket["cache_creates"] += row["cache_create_tokens"]
            bucket["tool_calls"] += row["tool_calls"]
            bucket["last_ts"] = max(bucket["last_ts"], row["ts"])
            latency[provider].append(row["latency_ms"])
        for provider, bucket in grouped.items():
            bucket["avg_latency"] = sum(latency[provider]) / len(latency[provider])
        return grouped
