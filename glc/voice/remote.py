"""Authenticated gateway-to-slot RPC for production voice providers."""

from __future__ import annotations

import base64
import os

import httpx

from glc.voice.stt.base import STTError, TranscribeResult
from glc.voice.tts.base import SynthesizeResult, TTSError


def _env_suffix(slot: str) -> str:
    return slot.upper()


def _endpoint(slot: str) -> tuple[str, str]:
    suffix = _env_suffix(slot)
    url = os.getenv(f"GLC_VOICE_URL_{suffix}", "").strip().rstrip("/")
    identity = os.getenv(f"GLC_SLOT_IDENTITY_{suffix}", "").strip()
    if not url or not identity:
        raise RuntimeError(f"isolated voice slot {slot!r} is not deployed")
    return url, identity


async def remote_transcribe(slot: str, audio: bytes, mime: str) -> TranscribeResult:
    try:
        url, identity = _endpoint(slot)
    except RuntimeError as exc:
        raise STTError(str(exc), status=503) from None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{url}/internal/transcribe",
                json={"audio_b64": base64.b64encode(audio).decode("ascii"), "mime": mime},
                headers={"Authorization": f"Bearer {identity}"},
            )
    except httpx.TimeoutException as exc:
        raise STTError("isolated STT provider request timed out", status=504) from exc
    except httpx.RequestError as exc:
        raise STTError("isolated STT provider request failed", status=502) from exc
    if response.status_code != 200:
        raise STTError("isolated STT provider request failed", status=response.status_code)
    return TranscribeResult(**response.json())


async def remote_synthesize(slot: str, text: str, voice_id: str | None = None) -> SynthesizeResult:
    try:
        url, identity = _endpoint(slot)
    except RuntimeError as exc:
        raise TTSError(str(exc), status=503) from None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{url}/internal/synthesize",
                json={"text": text, "voice_id": voice_id},
                headers={"Authorization": f"Bearer {identity}"},
            )
    except httpx.TimeoutException as exc:
        raise TTSError("isolated TTS provider request timed out", status=504) from exc
    except httpx.RequestError as exc:
        raise TTSError("isolated TTS provider request failed", status=502) from exc
    if response.status_code != 200:
        raise TTSError("isolated TTS provider request failed", status=response.status_code)
    return SynthesizeResult(**response.json())
