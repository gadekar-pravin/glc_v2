"""Strict schema for one authoritative provider-call ledger entry."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr

MAX_TOKENS_PER_FIELD = 10_000_000


class LedgerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[2] = 2
    event_id: StrictStr = Field(min_length=32, max_length=64, pattern=r"^[a-f0-9]+$")
    ts: StrictFloat = Field(gt=0)
    provider: StrictStr = Field(min_length=1, max_length=128)
    model: StrictStr = Field(min_length=1, max_length=256)
    input_tokens: StrictInt = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)
    output_tokens: StrictInt = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)
    cache_create_tokens: StrictInt = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)
    cache_read_tokens: StrictInt = Field(default=0, ge=0, le=MAX_TOKENS_PER_FIELD)
    latency_ms: StrictInt = Field(default=0, ge=0, le=86_400_000)
    status: Literal["ok", "error"] = "ok"
    error: StrictStr | None = Field(default=None, max_length=500)
    prompt_chars: StrictInt = Field(default=0, ge=0, le=100_000_000)
    response_chars: StrictInt = Field(default=0, ge=0, le=100_000_000)
    override: StrictStr | None = Field(default=None, max_length=128)
    attempted: StrictStr | None = Field(default=None, max_length=16_384)
    tool_calls: StrictInt = Field(default=0, ge=0, le=10_000)
    reasoning_applied: StrictBool = False
    tool_dialect: StrictStr | None = Field(default=None, max_length=64)
    call_role: StrictStr = Field(default="worker", min_length=1, max_length=64)
    router_decision: StrictStr | None = Field(default=None, max_length=64)
    embed_dim: StrictInt | None = Field(default=None, ge=0, le=10_000_000)
    agent: StrictStr | None = Field(default=None, min_length=1, max_length=256)
    session: StrictStr | None = Field(default=None, min_length=1, max_length=256)
    retries: StrictInt = Field(default=0, ge=0, le=100)
