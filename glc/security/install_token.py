"""FastAPI authentication dependency for the per-installation token."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Header, HTTPException

from glc.config import get_or_create_install_token


def require_install_token(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    """Require ``Authorization: Bearer <install_token>`` on an HTTP route."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="missing bearer token (Authorization: Bearer <install_token>)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    presented = authorization.removeprefix("Bearer ").strip()
    if not presented:
        raise HTTPException(
            status_code=401,
            detail="missing bearer token (Authorization: Bearer <install_token>)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expected = get_or_create_install_token()
    if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=403, detail="install token mismatch")
