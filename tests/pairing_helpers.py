"""Trusted test helpers for exercising the authenticated pairing semantics."""

from __future__ import annotations

from glc.security.pairing import PairingRecord, PairingStore


def pair_owner(
    store: PairingStore,
    channel: str,
    channel_user_id: str,
    user_handle: str = "owner",
) -> PairingRecord:
    """Seed an owner through the same issue/confirm flow used by control routes."""
    code, _ = store.issue_code(
        channel,
        channel_user_id,
        user_handle,
        requested_trust_level="owner_paired",
    )
    record = store.confirm_code(code)
    assert record is not None
    return record
