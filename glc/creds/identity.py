"""Authenticate a slot without trusting a caller-supplied slot name."""

from __future__ import annotations

import hmac
import os

from glc.isolation.manifest import Slot, all_slots


class IdentityError(Exception):
    pass


def identity_for_slot(slot: Slot) -> str | None:
    value = os.getenv(slot.identity_env, "").strip()
    return value or None


def authenticate_identity(authorization: str | None) -> Slot:
    if not authorization or not authorization.startswith("Bearer "):
        raise IdentityError("missing slot identity bearer token")
    presented = authorization.removeprefix("Bearer ").strip()
    if not presented:
        raise IdentityError("missing slot identity bearer token")

    matches: list[Slot] = []
    configured = 0
    for slot in all_slots():
        expected = identity_for_slot(slot)
        if expected is None:
            continue
        configured += 1
        if hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
            matches.append(slot)
    if configured == 0:
        raise IdentityError("no slot identities are configured")
    if len(matches) != 1:
        raise IdentityError("slot identity mismatch")
    return matches[0]
