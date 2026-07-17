"""WS /v1/channels/{name} — adapter control plane.

Adapters connect over WebSocket and exchange JSON-serialised
ChannelMessage and ChannelReply envelopes. The connection is gated by
the installation token presented in the Authorization header (Sec-Websocket
clients can pass it as a query string fallback, ?token=...).

This endpoint is the contract surface adapters speak to. The gateway
processes incoming messages through the rate limiter, allowlist,
trust-level classifier, policy engine, and (eventually) the agent
runtime. For S11 the agent runtime is a stub that echoes the message
back so adapter authors can verify their wire is plumbed correctly.
"""

from __future__ import annotations

import hmac
import json

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from glc.audit import append as audit_append
from glc.channels.envelope import ChannelIngress, ChannelMessage, ChannelReply
from glc.config import get_or_create_install_token
from glc.creds.identity import IdentityError, authenticate_identity
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store
from glc.security.rate_limits import get_rate_limiter
from glc.security.trust_level import classify

router = APIRouter()


@router.websocket("/v1/channels/{name}")
async def channel_ws(websocket: WebSocket, name: str, token: str | None = Query(default=None)):
    header_auth = websocket.headers.get("authorization") or websocket.headers.get("Authorization")
    presented = None
    if header_auth and header_auth.startswith("Bearer "):
        presented = header_auth.removeprefix("Bearer ").strip()
    elif token:
        presented = token
    expected = get_or_create_install_token()
    install_authenticated = bool(
        presented and hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
    )
    slot_authenticated = False
    if not install_authenticated and header_auth:
        try:
            slot = authenticate_identity(header_auth)
            slot_authenticated = slot.kind == "channel" and slot.name == name
        except IdentityError:
            slot_authenticated = False
    if not install_authenticated and not slot_authenticated:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    state = websocket.app.state
    registered = list(getattr(state, "registered_channels", []))
    if name not in registered:
        registered.append(name)
        state.registered_channels = registered

    limiter = get_rate_limiter()
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
                ingress = ChannelIngress.model_validate(payload)
            except Exception as e:
                await websocket.send_text(json.dumps({"error": f"invalid envelope: {e}"}))
                continue

            # The adapter controls every byte of the ingress envelope.  Bind
            # identity to the authenticated socket and derive trust from the
            # gateway-owned pairing database; never consume adapter claims.
            trusted = ingress.model_dump(exclude={"channel", "trust_level"})
            env = ChannelMessage(
                **trusted,
                channel=name,
                trust_level=classify(name, ingress.channel_user_id),
            )
            pairings = get_pairing_store()
            owners = [p.channel_user_id for p in pairings.owners(channel=name)]

            ok, why = allowed(
                env.channel,
                env.channel_user_id,
                owner_ids=owners,
                is_public_channel=bool(env.metadata.get("is_public_channel", False)),
                was_mentioned=bool(env.metadata.get("was_mentioned", False)),
            )
            if not ok:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=env.trust_level,
                    event_type="allowlist_drop",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"error": f"dropped: {why}"}))
                continue

            ok, why = limiter.check_message(env.channel, env.channel_user_id)
            if not ok:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=env.trust_level,
                    event_type="rate_limit",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"status": 429, "error": why}))
                continue

            audit_append(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                trust_level=env.trust_level,
                event_type="inbound_message",
                params={"text": env.text, "thread_id": env.thread_id},
            )

            # S11 stub agent: echo the text back so adapter authors can
            # verify the wire end-to-end. The real agent runtime hooks
            # in here in subsequent sessions.
            reply = ChannelReply(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                text=f"[glc echo] {env.text or ''}",
                thread_id=env.thread_id,
            )
            await websocket.send_text(reply.model_dump_json())
    except WebSocketDisconnect:
        return


@router.get("/v1/channels/{name}/webhook")
async def channel_webhook_verify(name: str):  # noqa: ARG001
    raise HTTPException(status_code=404, detail="webhooks run in isolated slot containers")


@router.post("/v1/channels/{name}/webhook")
async def channel_webhook(name: str):  # noqa: ARG001
    raise HTTPException(status_code=404, detail="webhooks run in isolated slot containers")
