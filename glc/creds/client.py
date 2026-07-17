"""Small client shipped in isolated slot images; it never reads provider keys."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class Token:
    access_token: str
    expires_at: int
    scope: str


def _slot() -> str:
    value = os.getenv("GLC_SLOT", "").strip()
    if not value:
        raise RuntimeError("GLC_SLOT is not configured")
    return value


def _identity() -> str:
    env_name = f"GLC_SLOT_IDENTITY_{_slot().upper()}"
    value = os.getenv(env_name, "").strip()
    if not value:
        raise RuntimeError(f"{env_name} is not configured")
    return value


def _gateway_url() -> str:
    value = os.getenv("GLC_GATEWAY_URL", "").strip().rstrip("/")
    if not value:
        raise RuntimeError("GLC_GATEWAY_URL is not configured")
    return value


async def get_token(*, tool: str, model: str | None = None) -> Token:
    body: dict[str, str] = {"tool": tool}
    if model:
        body["model"] = model
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"{_gateway_url()}/v1/creds/issue",
            json=body,
            headers={"Authorization": f"Bearer {_identity()}"},
        )
    if response.status_code != 200:
        raise RuntimeError(f"credential issuance failed with HTTP {response.status_code}")
    data = response.json()
    return Token(
        access_token=data["access_token"],
        expires_at=int(data["expires_at"]),
        scope=data["scope"],
    )
