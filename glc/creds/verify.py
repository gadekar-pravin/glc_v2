"""Verify exact tool scope and atomically consume a credential once."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt

from glc import db
from glc.creds.issuer import ALGORITHM, AUDIENCE, ISSUER, signing_key


class CredentialError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class VerifiedCredential:
    slot: str
    tool: str
    model: str | None
    expires_at: int
    jti: str


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise CredentialError("missing tool credential")
    value = authorization.removeprefix("Bearer ").strip()
    if not value:
        raise CredentialError("missing tool credential")
    return value


def verify_and_consume(
    authorization: str | None,
    *,
    expected_tool: str,
    expected_models: set[str | None] | None = None,
    now: int | None = None,
) -> VerifiedCredential:
    try:
        claims: dict[str, Any] = jwt.decode(
            _bearer(authorization),
            signing_key(),
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["iss", "aud", "sub", "tool", "iat", "nbf", "exp", "jti"]},
        )
    except CredentialError:
        raise
    except jwt.ExpiredSignatureError:
        raise CredentialError("tool credential expired") from None
    except jwt.ImmatureSignatureError:
        raise CredentialError("tool credential is not active") from None
    except jwt.InvalidTokenError:
        raise CredentialError("invalid tool credential") from None

    tool = str(claims["tool"])
    if tool != expected_tool:
        raise CredentialError("tool credential scope mismatch", status_code=403)
    model = claims.get("model")
    if model is not None:
        models = expected_models or set()
        if models != {str(model)}:
            raise CredentialError("tool credential model mismatch", status_code=403)

    checked_at = int(time.time()) if now is None else int(now)
    jti = str(claims["jti"])
    if not db.consume_credential(
        jti=jti,
        slot=str(claims["sub"]),
        tool=tool,
        model=str(model) if model is not None else None,
        now=checked_at,
    ):
        raise CredentialError("tool credential is unknown, expired, or already used")

    return VerifiedCredential(
        slot=str(claims["sub"]),
        tool=tool,
        model=str(model) if model is not None else None,
        expires_at=int(claims["exp"]),
        jti=jti,
    )
