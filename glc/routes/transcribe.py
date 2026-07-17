"""POST /v1/transcribe — STT through the voice routing layer."""

from __future__ import annotations

import base64
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from glc.creds.auth import authorize_tool_request
from glc.voice.remote import remote_transcribe
from glc.voice.stt import STTError, transcribe
from glc.voice.stt.router import PREFER_TO_PROVIDER

router = APIRouter()


class TranscribeRequest(BaseModel):
    audio_b64: str
    mime: str = "audio/wav"
    agent: str | None = None
    prefer: Literal["default", "local", "streaming"] = "default"


class TranscribeResponse(BaseModel):
    text: str
    language: str
    duration_ms: int
    provider: str
    cost_usd: float = Field(default=0.0)


@router.post("/v1/transcribe", response_model=TranscribeResponse)
async def transcribe_route(
    req: TranscribeRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    authorize_tool_request(request, authorization, tool="stt.transcribe")
    if req.prefer == "streaming":
        raise HTTPException(
            400,
            "streaming STT is not exposed through POST /v1/transcribe. "
            "Open a Gemini Live WebSocket session (S12 deliverable).",
        )
    try:
        audio = base64.b64decode(req.audio_b64)
    except Exception as e:
        raise HTTPException(400, f"audio_b64 is not valid base64: {e}") from e
    try:
        if bool(getattr(request.app.state, "production", False)):
            r = await remote_transcribe(f"stt_{PREFER_TO_PROVIDER[req.prefer]}", audio, req.mime)
        else:
            r = await transcribe(audio, req.mime, prefer=req.prefer)
    except STTError as e:
        raise HTTPException(e.status or 502, str(e)) from e
    return TranscribeResponse(
        text=r.text,
        language=r.language,
        duration_ms=r.duration_ms,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
