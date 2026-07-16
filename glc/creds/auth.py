"""Dual authentication for trusted install clients and isolated slots."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import HTTPException, Request

from glc.config import get_or_create_install_token
from glc.creds.verify import CredentialError, VerifiedCredential, verify_and_consume


@dataclass(frozen=True)
class ToolPrincipal:
    kind: str
    slot: str | None = None


def _presented(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    value = authorization.removeprefix("Bearer ").strip()
    return value or None


def authorize_tool_request(
    request: Request,
    authorization: str | None,
    *,
    tool: str,
    expected_models: set[str | None] | None = None,
) -> ToolPrincipal:
    """Accept the install token or consume one exact slot credential in production."""
    value = _presented(authorization)
    if value is not None and hmac.compare_digest(
        value.encode("utf-8"), get_or_create_install_token().encode("utf-8")
    ):
        return ToolPrincipal(kind="install")

    if not bool(getattr(request.app.state, "production", False)) and value is None:
        return ToolPrincipal(kind="local")

    try:
        verified: VerifiedCredential = verify_and_consume(
            authorization,
            expected_tool=tool,
            expected_models=expected_models,
        )
    except CredentialError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None,
        ) from None
    return ToolPrincipal(kind="slot", slot=verified.slot)
