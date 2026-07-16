"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from glc.creds.auth import authorize_tool_request
from glc.voice.remote import remote_synthesize
from glc.voice.tts import TTSError, synthesize
from glc.voice.tts.router import PREFER_TO_PROVIDER

router = APIRouter()


class SpeakRequest(BaseModel):
    text: str
    voice_id: str | None = None
    agent: str | None = None
    prefer: Literal["default", "quality", "streaming", "realtime", "fallback"] = "default"


class SpeakResponse(BaseModel):
    audio_b64: str
    mime: str
    sample_rate: int
    provider: str
    cost_usd: float = 0.0


@router.post("/v1/speak", response_model=SpeakResponse)
async def speak_route(
    req: SpeakRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    authorize_tool_request(request, authorization, tool="tts.synthesize")
    try:
        if bool(getattr(request.app.state, "production", False)) and req.prefer != "fallback":
            r = await remote_synthesize(f"tts_{PREFER_TO_PROVIDER[req.prefer]}", req.text, req.voice_id)
        else:
            r = await synthesize(req.text, voice_id=req.voice_id, prefer=req.prefer)
    except TTSError as e:
        raise HTTPException(e.status or 502, str(e)) from e
    return SpeakResponse(
        audio_b64=r.audio_b64,
        mime=r.mime,
        sample_rate=r.sample_rate,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
