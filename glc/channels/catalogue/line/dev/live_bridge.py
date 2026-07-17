"""Isolated FastAPI slot runtime for real LINE webhooks.

This process verifies and parses provider events, forwards the resulting
``ChannelIngress`` to the authenticated gateway WebSocket, then translates the
gateway reply back to LINE.  It never reads pairing state or assigns trust.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
import websockets
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request

from glc.channels.catalogue.line.adapter import Adapter, LineTransport
from glc.channels.envelope import ChannelIngress, ChannelReply

LINE_MESSAGE_API = "https://api.line.me/v2/bot/message"
DEFAULT_GATEWAY_WS_URL = "ws://127.0.0.1:8111/v1/channels/line"

RelayGateway = Callable[[ChannelIngress], Awaitable[ChannelReply | dict[str, Any]]]


@dataclass(frozen=True)
class BridgeConfig:
    access_token: str | None
    channel_secret: str | None
    gateway_ws_url: str
    slot_identity: str | None

    @classmethod
    def from_env(cls) -> BridgeConfig:
        load_dotenv()
        return cls(
            access_token=os.getenv("LINE_CHANNEL_ACCESS_TOKEN"),
            channel_secret=os.getenv("LINE_CHANNEL_SECRET"),
            gateway_ws_url=os.getenv("GLC_GATEWAY_WS_URL", DEFAULT_GATEWAY_WS_URL),
            slot_identity=os.getenv("GLC_SLOT_IDENTITY_LINE"),
        )


class RealLineTransport:
    """Reference ``LineTransport`` implementation: calls LINE's Messaging API
    over httpx (duck-typed replacement for ``LineMock``)."""

    def __init__(self, access_token: str) -> None:
        self._access_token = access_token
        self._reply_tokens: dict[str, tuple[str, float]] = {}

    def set_reply_token(self, user_id: str, token: str, ttl_s: float = 60.0) -> None:
        self._reply_tokens[user_id] = (token, time.time() + ttl_s)

    def consume_reply_token(self, user_id: str) -> str | None:
        item = self._reply_tokens.pop(user_id, None)
        if item is None:
            return None
        token, expires_at = item
        return token if expires_at >= time.time() else None

    def pop_disconnect(self) -> bool:
        return False

    async def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        endpoint = "/reply" if "replyToken" in payload else "/push"
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(f"{LINE_MESSAGE_API}{endpoint}", headers=headers, json=payload)

        try:
            body: Any = response.json()
        except ValueError:
            body = {"text": response.text}

        result = {
            "endpoint": endpoint,
            "status": response.status_code,
            "body": body,
            "x_line_request_id": response.headers.get("x-line-request-id"),
        }
        print(f"[line] outbound endpoint={endpoint} status={response.status_code}", flush=True)
        return result


def verify_line_signature(body: bytes, signature: str | None, channel_secret: str) -> bool:
    digest = hmac.new(channel_secret.encode("utf-8"), body, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(expected, signature or "")


def line_signature(body: bytes, channel_secret: str) -> str:
    """Generate a LINE-compatible signature for local smoke tests."""
    digest = hmac.new(channel_secret.encode("utf-8"), body, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def _status(result: Any) -> int:
    if isinstance(result, dict) and isinstance(result.get("status"), int):
        return int(result["status"])
    return 200


def _endpoint(result: Any) -> str | None:
    if isinstance(result, dict) and isinstance(result.get("endpoint"), str):
        return result["endpoint"]
    return None


async def relay_via_gateway(
    message: ChannelIngress, *, config: BridgeConfig
) -> ChannelReply | dict[str, Any]:
    """Send provider facts to the trusted gateway and return its decision."""
    if not config.slot_identity:
        raise RuntimeError("GLC_SLOT_IDENTITY_LINE is not configured")
    headers = {"Authorization": f"Bearer {config.slot_identity}"}
    async with websockets.connect(config.gateway_ws_url, additional_headers=headers) as websocket:
        await websocket.send(message.model_dump_json())
        payload = json.loads(await websocket.recv())
    if "error" in payload or payload.get("status") == 429:
        return payload
    return ChannelReply.model_validate(payload)


async def handle_text_event(
    *,
    adapter: Adapter,
    event: dict[str, Any],
    destination: str | None,
    config: BridgeConfig,
    relay_gateway: RelayGateway,
) -> dict[str, Any]:
    message = await adapter.on_message({"destination": destination, "events": [event]})
    if message is None:
        print("[line] inbound dropped before relay", flush=True)
        return {"agent_called": False, "dropped": True}

    print(f"[line] inbound user_id={message.channel_user_id} text={message.text!r}", flush=True)

    decision = await relay_gateway(message)
    if isinstance(decision, dict):
        return {
            "user_id": message.channel_user_id,
            "gateway_called": True,
            "dropped": "error" in decision,
            "rate_limited": decision.get("status") == 429,
            "gateway_result": decision,
        }

    reply_result = await adapter.send(decision)
    return {
        "user_id": message.channel_user_id,
        "gateway_called": True,
        "reply_status": _status(reply_result),
        "reply_endpoint": _endpoint(reply_result),
    }


def create_app(
    *,
    config: BridgeConfig | None = None,
    transport: Any | None = None,
    relay_gateway: RelayGateway | None = None,
) -> FastAPI:
    config = config or BridgeConfig.from_env()
    if transport is None and config.access_token:
        # Typed binding so mypy checks RealLineTransport satisfies LineTransport.
        real: LineTransport = RealLineTransport(config.access_token)
        transport = real

    app = FastAPI(title="GLC LINE to EAG3-09 bridge")
    adapter = Adapter(config={"transport": transport}) if transport is not None else None

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "line_configured": bool(config.channel_secret and transport is not None),
            "gateway_configured": bool(config.slot_identity and config.gateway_ws_url),
        }

    async def _line_webhook(request: Request, x_line_signature: str | None) -> dict[str, Any]:
        if not config.channel_secret or adapter is None:
            raise HTTPException(status_code=503, detail="LINE bridge is not configured")

        body = await request.body()
        if not verify_line_signature(body, x_line_signature, config.channel_secret):
            raise HTTPException(status_code=403, detail="bad LINE signature")

        try:
            raw = json.loads(body or b"{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc

        events = raw.get("events") or []
        if not events:
            print("[line] webhook verification ping: no events", flush=True)
            return {"ok": True, "events": 0, "handled": 0, "skipped": 0, "results": []}

        gateway_fn = relay_gateway
        if gateway_fn is None:

            async def default_gateway_fn(message: ChannelIngress) -> ChannelReply | dict[str, Any]:
                return await relay_via_gateway(message, config=config)

            gateway_fn = default_gateway_fn

        handled = 0
        skipped = 0
        results: list[dict[str, Any]] = []
        for event in events:
            if event.get("type") != "message":
                skipped += 1
                continue
            if (event.get("message") or {}).get("type") != "text":
                skipped += 1
                continue
            handled += 1
            results.append(
                await handle_text_event(
                    adapter=adapter,
                    event=event,
                    destination=raw.get("destination"),
                    config=config,
                    relay_gateway=gateway_fn,
                )
            )

        return {"ok": True, "events": len(events), "handled": handled, "skipped": skipped, "results": results}

    @app.post("/callback")
    async def callback(
        request: Request, x_line_signature: str | None = Header(default=None)
    ) -> dict[str, Any]:
        return await _line_webhook(request, x_line_signature)

    return app


app = create_app()
