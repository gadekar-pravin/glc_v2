"""Gateway-only issuer for five-minute, single-use tool credentials."""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

import jwt

from glc import db
from glc.isolation.manifest import SUPPORTED_TOOLS, Slot

ALGORITHM = "HS256"
ISSUER = "glc-gateway"
AUDIENCE = "glc-tools"
DEFAULT_TTL_SECONDS = 300
MODEL_SCOPED_TOOLS = frozenset({"llm.chat", "llm.chat.batch", "llm.vision"})


def signing_key() -> str:
    value = os.getenv("GLC_CREDS_SIGNING_KEY", "").strip()
    if not value:
        raise RuntimeError("GLC_CREDS_SIGNING_KEY is not configured")
    if len(value.encode("utf-8")) < 32:
        raise RuntimeError("GLC_CREDS_SIGNING_KEY must be at least 32 bytes")
    return value


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    expires_at: int
    scope: str


def issue_token(
    *,
    slot: Slot,
    tool: str,
    model: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: int | None = None,
) -> IssuedToken:
    if tool not in SUPPORTED_TOOLS:
        raise ValueError(f"unsupported tool {tool!r}")
    if model is not None and tool not in MODEL_SCOPED_TOOLS:
        raise ValueError(f"tool {tool!r} does not support model-scoped credentials")
    if tool not in slot.allowed_tools:
        raise PermissionError(f"slot {slot.name!r} is not allowed to request {tool!r}")
    if ttl_seconds <= 0 or ttl_seconds > DEFAULT_TTL_SECONDS:
        raise ValueError("credential TTL must be between 1 and 300 seconds")

    issued_at = int(time.time()) if now is None else int(now)
    expires_at = issued_at + ttl_seconds
    jti = secrets.token_urlsafe(24)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": slot.name,
        "tool": tool,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "jti": jti,
    }
    if model:
        claims["model"] = model

    db.register_credential(
        jti=jti,
        slot=slot.name,
        tool=tool,
        model=model,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    encoded = jwt.encode(claims, signing_key(), algorithm=ALGORITHM)
    scope = f"{tool}:{model}" if model else tool
    return IssuedToken(access_token=encoded, expires_at=expires_at, scope=scope)
