"""Uniform authenticated ASGI runtime used by isolated voice slot images."""

from __future__ import annotations

import base64
import importlib
import os
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from glc.isolation.manifest import get_slot

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)


def _slot_and_identity(authorization: str | None):
    slot_name = os.getenv("GLC_SLOT", "").strip()
    try:
        slot = get_slot(slot_name)
    except KeyError:
        raise HTTPException(503, "voice slot is not configured") from None
    expected = os.getenv(slot.identity_env, "").strip()
    presented = ""
    if authorization and authorization.startswith("Bearer "):
        presented = authorization.removeprefix("Bearer ").strip()
    import hmac

    if not expected or not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(401, "voice slot identity mismatch")
    if slot.kind != "voice":
        raise HTTPException(503, "configured slot is not a voice provider")
    return slot


class STTRequest(BaseModel):
    audio_b64: str
    mime: str


class TTSRequest(BaseModel):
    text: str
    voice_id: str | None = None


@app.post("/internal/transcribe")
async def transcribe(
    req: STTRequest,
    authorization: Annotated[str | None, Header()] = None,
):
    slot = _slot_and_identity(authorization)
    if slot.runtime != "stt":
        raise HTTPException(404, "not an STT slot")
    module = importlib.import_module(f"{slot.package}.adapter")
    provider = module.Provider()
    result = await provider.transcribe(base64.b64decode(req.audio_b64), req.mime)
    return result.__dict__


@app.post("/internal/synthesize")
async def synthesize(
    req: TTSRequest,
    authorization: Annotated[str | None, Header()] = None,
):
    slot = _slot_and_identity(authorization)
    if slot.runtime != "tts":
        raise HTTPException(404, "not a TTS slot")
    module = importlib.import_module(f"{slot.package}.adapter")
    provider = module.Provider()
    result = await provider.synthesize(req.text, req.voice_id)
    return result.__dict__
