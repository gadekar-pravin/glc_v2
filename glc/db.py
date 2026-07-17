"""Gateway credential registry.

The cost ledger deliberately does not expose a module-level write function.
Authoritative call accounting lives behind the lifespan-owned signed writer
in :mod:`glc.ledger`.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
DB_PATH = os.getenv("GLC_GATEWAY_DB", str(DEFAULT_DIR / "gateway.sqlite"))


def _ensure_parent() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def conn():
    _ensure_parent()
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init() -> None:
    with conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS issued_credentials (
                jti_hash TEXT PRIMARY KEY,
                slot TEXT NOT NULL,
                tool TEXT NOT NULL,
                model TEXT,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            )"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_credential_expiry ON issued_credentials(expires_at)")


def _jti_hash(jti: str) -> str:
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


def register_credential(
    *,
    jti: str,
    slot: str,
    tool: str,
    model: str | None,
    issued_at: int,
    expires_at: int,
) -> None:
    with conn() as c:
        c.execute("DELETE FROM issued_credentials WHERE expires_at < ?", (issued_at,))
        c.execute(
            """INSERT INTO issued_credentials
               (jti_hash, slot, tool, model, issued_at, expires_at, used_at)
               VALUES (?, ?, ?, ?, ?, ?, NULL)""",
            (_jti_hash(jti), slot, tool, model, issued_at, expires_at),
        )


def consume_credential(*, jti: str, slot: str, tool: str, model: str | None, now: int) -> bool:
    """Atomically change exactly one matching unexpired grant from unused to used."""
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        cursor = c.execute(
            """UPDATE issued_credentials SET used_at = ?
               WHERE jti_hash = ? AND slot = ? AND tool = ?
                 AND model IS ? AND used_at IS NULL AND expires_at >= ?""",
            (now, _jti_hash(jti), slot, tool, model, now),
        )
        return cursor.rowcount == 1
