"""Long-polling Telegram runtime and safe isolation probe for Modal."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import httpx
import websockets

from glc.channels.catalogue.telegram.adapter import Adapter
from glc.channels.envelope import ChannelReply
from glc.creds.client import get_token
from glc.isolation.manifest import PROVIDER_SECRET_KEYS, get_slot


def _gateway_url() -> str:
    value = os.getenv("GLC_GATEWAY_URL", "").strip().rstrip("/")
    if not value:
        raise RuntimeError("GLC_GATEWAY_URL is not configured")
    return value


def _identity() -> str:
    slot = get_slot("telegram")
    value = os.getenv(slot.identity_env, "").strip()
    if not value:
        raise RuntimeError(f"{slot.identity_env} is not configured")
    return value


def _ws_url() -> str:
    url = _gateway_url()
    if url.startswith("https://"):
        return f"wss://{url.removeprefix('https://')}/v1/channels/telegram"
    if url.startswith("http://"):
        return f"ws://{url.removeprefix('http://')}/v1/channels/telegram"
    raise RuntimeError("GLC_GATEWAY_URL must start with http:// or https://")


async def run() -> None:
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured")
    adapter = Adapter()
    headers = {"Authorization": f"Bearer {_identity()}"}
    async with websockets.connect(_ws_url(), additional_headers=headers) as websocket:
        offset = 0

        async def poll() -> None:
            nonlocal offset
            async with httpx.AsyncClient(timeout=15.0) as client:
                while True:
                    response = await client.get(
                        f"https://api.telegram.org/bot{bot_token}/getUpdates",
                        params={"offset": offset, "timeout": 10},
                    )
                    if response.status_code == 200:
                        payload = response.json()
                        for update in payload.get("result", ()) if payload.get("ok") else ():
                            offset = int(update["update_id"]) + 1
                            message = await adapter.on_message(update)
                            if message is not None:
                                await websocket.send(message.model_dump_json())
                    await asyncio.sleep(1)

        async def replies() -> None:
            async for raw in websocket:
                payload = json.loads(raw)
                if "error" not in payload:
                    await adapter.send(ChannelReply.model_validate(payload))

        await asyncio.gather(poll(), replies())


async def security_probe() -> dict[str, Any]:
    """Return booleans/statuses only. Secret values never enter the result."""
    provider_keys_absent = {name: name not in os.environ for name in sorted(PROVIDER_SECRET_KEYS)}
    chat_token = await get_token(tool="llm.chat")
    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {"Authorization": f"Bearer {chat_token.access_token}"}
        first = await client.post(
            f"{_gateway_url()}/v1/chat",
            json={"prompt": "credential isolation probe", "provider": "gemini"},
            headers=headers,
        )
        replay = await client.post(
            f"{_gateway_url()}/v1/chat",
            json={"prompt": "credential replay probe", "provider": "gemini"},
            headers=headers,
        )

        cross_token = await get_token(tool="llm.chat")
        cross_headers = {"Authorization": f"Bearer {cross_token.access_token}"}
        cross_tool = await client.post(
            f"{_gateway_url()}/v1/speak",
            json={"text": "must be denied"},
            headers=cross_headers,
        )
        intended_after_denial = await client.post(
            f"{_gateway_url()}/v1/chat",
            json={"prompt": "scope denial did not consume", "provider": "gemini"},
            headers=cross_headers,
        )
    return {
        "provider_keys_absent": provider_keys_absent,
        "first_status": first.status_code,
        "replay_status": replay.status_code,
        "cross_tool_status": cross_tool.status_code,
        "intended_after_denial_status": intended_after_denial.status_code,
    }
