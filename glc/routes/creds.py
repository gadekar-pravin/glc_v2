"""Issue a single-use, exact-scope credential to an authenticated slot."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from glc.creds.identity import IdentityError, authenticate_identity
from glc.creds.issuer import issue_token

router = APIRouter()

ToolName = Literal[
    "llm.chat",
    "llm.chat.batch",
    "llm.vision",
    "llm.embed",
    "stt.transcribe",
    "tts.synthesize",
]


class CredsIssueRequest(BaseModel):
    tool: ToolName
    model: str | None = None


class CredsIssueResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: int
    scope: str


@router.post("/v1/creds/issue", response_model=CredsIssueResponse)
async def creds_issue(
    req: CredsIssueRequest,
    authorization: Annotated[str | None, Header()] = None,
) -> CredsIssueResponse:
    try:
        slot = authenticate_identity(authorization)
    except IdentityError as exc:
        raise HTTPException(
            status_code=401, detail=str(exc), headers={"WWW-Authenticate": "Bearer"}
        ) from None
    try:
        token = issue_token(slot=slot, tool=req.tool, model=req.model)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return CredsIssueResponse(
        access_token=token.access_token,
        expires_at=token.expires_at,
        scope=token.scope,
    )
