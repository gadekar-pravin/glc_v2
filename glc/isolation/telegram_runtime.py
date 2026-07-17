"""Long-polling Telegram runtime and safe isolation probe for Modal."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from importlib import import_module
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
    install_token_env_absent = "GLC_INSTALL_TOKEN" not in os.environ
    ledger_signing_key_absent = "GLC_LEDGER_SIGNING_KEY" not in os.environ
    install_token_path = os.path.join(os.getenv("GLC_CONFIG_DIR", "."), "install_token")
    install_token_file_readable = os.path.isfile(install_token_path) and os.access(
        install_token_path, os.R_OK
    )
    try:
        pairing = import_module("glc.security.pairing")
        pairing_api_absent = not hasattr(pairing.get_pairing_store(), "force_pair_owner")
    except ModuleNotFoundError:
        pairing_api_absent = True

    try:
        ledger_db = import_module("glc.db")
        unsigned_ledger_api_absent = not hasattr(ledger_db, "log_call")
    except ModuleNotFoundError:
        unsigned_ledger_api_absent = True

    try:
        import_module("glc.ledger.writer")
        ledger_package_absent = False
    except ModuleNotFoundError:
        ledger_package_absent = True

    forged_owner_rejected = False
    headers = {"Authorization": f"Bearer {_identity()}"}
    async with websockets.connect(_ws_url(), additional_headers=headers) as websocket:
        await websocket.send(
            json.dumps(
                {
                    "channel": "discord",
                    "channel_user_id": "leak-3-attacker",
                    "user_handle": "attacker",
                    "text": "pairing boundary probe",
                    "trust_level": "owner_paired",
                    "arrived_at": datetime.now(UTC).isoformat(),
                    "metadata": {"is_public_channel": False, "was_mentioned": False},
                }
            )
        )
        response = json.loads(await websocket.recv())
        forged_owner_rejected = "dropped" in response.get("error", "")

    chat_token = await get_token(tool="llm.chat")
    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {"Authorization": f"Bearer {chat_token.access_token}"}
        first = await client.post(
            f"{_gateway_url()}/v1/chat",
            json={
                "prompt": "credential and ledger isolation probe",
                "provider": "gemini",
                "agent": "victim",
            },
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
        "install_token_env_absent": install_token_env_absent,
        "ledger_signing_key_absent": ledger_signing_key_absent,
        "install_token_file_readable": install_token_file_readable,
        "pairing_api_absent": pairing_api_absent,
        "unsigned_ledger_api_absent": unsigned_ledger_api_absent,
        "ledger_package_absent": ledger_package_absent,
        "forged_owner_rejected": forged_owner_rejected,
        "first_status": first.status_code,
        "replay_status": replay.status_code,
        "cross_tool_status": cross_tool.status_code,
        "intended_after_denial_status": intended_after_denial.status_code,
    }
