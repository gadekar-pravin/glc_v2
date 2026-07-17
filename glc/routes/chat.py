"""V9-compatibility routes: /v1/chat, /v1/chat/batch, /v1/providers,
/v1/capabilities, /v1/status, /v1/routers, /v1/calls.

This module is a near-verbatim port of llm_gatewayV9/main.py's chat
pipeline. Bare imports were rewritten as package-relative imports; the
V9 fixes (json_object hint injection, Gemini cooldown handling, day
rollover, default URL inheritance) are preserved verbatim. Do not
regress them — tests in test_v9_compat.py assert behaviour shape.
"""

from __future__ import annotations

import asyncio as _asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from jsonschema import Draft202012Validator, ValidationError

from glc import providers as P
from glc.creds.auth import authorize_tool_request
from glc.llm_schemas import (
    BatchChatRequest,
    ChatRequest,
    ChatResponse,
    EmbedRequest,
    EmbedResponse,
    ResponseFormat,
    RouterDecision,
    ToolCall,
    VisionRequest,
)
from glc.routing import DEFAULT_ROUTER_ORDER, LIMITS, SHORTCUTS
from glc.security.image_urls import ImageURLFetchError, fetch_image_as_data_url
from glc.security.install_token import require_install_token

logger = logging.getLogger(__name__)

PUBLIC_UPSTREAM_ERROR = "upstream provider request failed"

DEFAULT_ORDER = ["ollama", "gemini", "nvidia", "groq", "cerebras", "openrouter", "github"]
ORDER = [x.strip() for x in os.getenv("LLM_ORDER", ",".join(DEFAULT_ORDER)).split(",") if x.strip()]
ROUTER_ORDER = [
    x.strip() for x in os.getenv("ROUTER_ORDER", ",".join(DEFAULT_ROUTER_ORDER)).split(",") if x.strip()
]

_AGENT_ROUTING_PATH = Path(__file__).parent.parent / "agent_routing.yaml"
AGENT_ROUTING: dict[str, str] = {}
if _AGENT_ROUTING_PATH.exists():
    try:
        AGENT_ROUTING = yaml.safe_load(_AGENT_ROUTING_PATH.read_text()) or {}
    except Exception as e:  # pragma: no cover
        print(f"[glc] failed to parse agent_routing.yaml: {e!r}")

TIER_TO_ORDER = {
    "TINY": ["github", "openrouter", "groq", "nvidia", "cerebras", "gemini", "ollama"],
    "LARGE": ["gemini", "groq", "nvidia", "cerebras", "github", "openrouter", "ollama"],
}

ROUTER_SAMPLE_HEAD = 400
ROUTER_SAMPLE_TAIL = 400
ROUTER_PROMPT = (
    "You are a routing classifier. Given a token_count and a content sample, "
    "output exactly one of: TINY, LARGE, or HUGE.\n\n"
    "Rules:\n"
    "- TINY: token_count below 1000 with simple factual content.\n"
    "- LARGE: token_count between 1000 and 8000, OR token_count below 1000 "
    "but content is dense (code, base64, multilingual, technical).\n"
    "- HUGE: token_count above 8000.\n\n"
    "Output the single word and nothing else."
)

router = APIRouter()


# ─────────────────────────── helpers (verbatim port) ──────────────────────────


def _estimate_tokens(text: str) -> int:
    return int(len(text.split()) * 1.4)


def _build_sample(text: str) -> str:
    if len(text) <= ROUTER_SAMPLE_HEAD + ROUTER_SAMPLE_TAIL + 10:
        return text
    return text[:ROUTER_SAMPLE_HEAD] + "\n...\n" + text[-ROUTER_SAMPLE_TAIL:]


def _tier_from_count(tokens: int) -> str:
    if tokens > 8000:
        return "HUGE"
    if tokens >= 1000:
        return "LARGE"
    return "TINY"


def _parse_tier(text: str) -> str | None:
    up = (text or "").upper()
    for tier in ("HUGE", "LARGE", "TINY"):
        if tier in up:
            return tier
    return None


async def _classify_tier(req, role, router_pool, prompt_text, ledger):
    estimated = _estimate_tokens(prompt_text)
    if estimated > 8000:
        return RouterDecision(
            role=role,
            tier="HUGE",
            estimated_tokens=estimated,
            router_provider="(skipped)",
            router_model="(skipped)",
            router_latency_ms=0,
            fallback_used=True,
        )
    sample = _build_sample(prompt_text)
    envelope = f"token_count: {estimated}\nsample:\n{sample}"
    call_role = f"router_{role}"
    last_provider = last_model = ""
    last_latency = 0
    for name in router_pool.candidates():
        ok, _ = router_pool.state[name].can_use(LIMITS[name], 400)
        if not ok:
            continue
        provider = router_pool.providers[name]
        t0 = time.time()
        router_pool.state[name].record(0)
        last_provider, last_model = name, provider.model
        try:
            result = await provider.chat(
                messages=[{"role": "user", "content": envelope}],
                system_blocks=ROUTER_PROMPT,
                max_tokens=8,
                temperature=0,
                model=None,
                tools=None,
                tool_choice=None,
                reasoning="off",
                response_format=None,
                cache_system=False,
            )
            latency = int((time.time() - t0) * 1000)
            last_latency = latency
            tokens = (result.get("input_tokens") or 0) + (result.get("output_tokens") or 0)
            router_pool.state[name].tokens_today += tokens
            router_pool.state[name].tokens_minute.append((time.time(), tokens))
            tier = _parse_tier(result.get("text", ""))
            if tier == "HUGE" and estimated <= 8000:
                tier = "LARGE"
            if tier is None:
                logger.warning(
                    "Router provider returned an unparseable tier (provider=%s, reply=%r)",
                    name,
                    result.get("text", "")[:100],
                )
                ledger.log_call(
                    provider=name,
                    model=result.get("model", provider.model),
                    input_tokens=result.get("input_tokens", 0),
                    output_tokens=result.get("output_tokens", 0),
                    latency_ms=latency,
                    status="error",
                    error=PUBLIC_UPSTREAM_ERROR,
                    prompt_chars=len(envelope),
                    call_role=call_role,
                    router_decision="unparseable",
                )
                continue
            ledger.log_call(
                provider=name,
                model=result.get("model", provider.model),
                input_tokens=result.get("input_tokens", 0),
                output_tokens=result.get("output_tokens", 0),
                latency_ms=latency,
                status="ok",
                prompt_chars=len(envelope),
                response_chars=len(result.get("text", "")),
                call_role=call_role,
                router_decision=tier,
            )
            return RouterDecision(
                role=role,
                tier=tier,
                estimated_tokens=estimated,
                router_provider=name,
                router_model=result.get("model", provider.model),
                router_latency_ms=latency,
                fallback_used=False,
            )
        except Exception:
            latency = int((time.time() - t0) * 1000)
            last_latency = latency
            logger.exception("Router provider request failed (provider=%s)", name)
            ledger.log_call(
                provider=name,
                model=provider.model,
                status="error",
                error=PUBLIC_UPSTREAM_ERROR,
                latency_ms=latency,
                call_role=call_role,
                router_decision="error",
            )
            continue
    return RouterDecision(
        role=role,
        tier=_tier_from_count(estimated),
        estimated_tokens=estimated,
        router_provider=last_provider or "(unavailable)",
        router_model=last_model or "(unavailable)",
        router_latency_ms=last_latency,
        fallback_used=True,
    )


def _normalize_messages(req: ChatRequest):
    if req.messages:
        return list(req.messages)
    return [{"role": "user", "content": req.prompt or ""}]


def _system_blocks(req: ChatRequest):
    if req.system is None:
        return None
    if isinstance(req.system, str):
        if req.cache_system:
            return [{"text": req.system, "cache": True}]
        return req.system
    return [b.model_dump() if hasattr(b, "model_dump") else b for b in req.system]


def _est_tokens(messages, system_blocks, max_tokens):
    chars = 0
    for m in messages:
        c = m.get("content", "")
        if isinstance(c, list):
            chars += len(P._extract_text_blocks(c))
            chars += 1200 * sum(
                1 for b in c if isinstance(b, dict) and b.get("type") in ("image_url", "image", "input_image")
            )
        else:
            chars += len(str(c))
    if isinstance(system_blocks, str):
        chars += len(system_blocks)
    elif isinstance(system_blocks, list):
        for b in system_blocks:
            chars += len(b.get("text", "") if isinstance(b, dict) else "")
    return chars // 4 + max_tokens


def _backoff_for(err: Exception, has_model_override: bool = False):
    msg = str(err).lower()
    status = getattr(err, "status", None)
    if status == 429:
        if "queue" in msg:
            return 15, "server queue full"
        if "quota" in msg or "rpm" in msg or "per minute" in msg:
            return 60, "RPM quota burned"
        if "rpd" in msg or "per day" in msg or "daily" in msg:
            return 3600, "RPD quota burned"
        return 30, "rate limited"
    if status and 500 <= status < 600:
        return 20, f"upstream {status}"
    if status == 408 or "timeout" in msg:
        return 10, "timeout"
    if status in (401, 403):
        if has_model_override:
            return 0, ""
        return 600, "auth error"
    if status == 404 and has_model_override:
        return 0, ""
    return 0, ""


def _attempts_str(attempts):
    return "; ".join(f"{a['provider']}:{a['reason']}" for a in attempts)


def _public_attempts(attempts):
    return [
        {**attempt, "reason": PUBLIC_UPSTREAM_ERROR}
        if isinstance(attempt, dict) and attempt.get("reason")
        else attempt
        for attempt in attempts
    ]


def _sanitize_persisted_attempted(value):
    if not isinstance(value, str) or not value:
        return value
    sanitized = []
    for attempt in value.split("; "):
        provider, separator, _reason = attempt.partition(":")
        sanitized.append(f"{provider}:{PUBLIC_UPSTREAM_ERROR}" if separator else PUBLIC_UPSTREAM_ERROR)
    return "; ".join(sanitized)


def _required_caps(req: ChatRequest):
    caps = []
    if req.tools:
        caps.append("tools")
    if req.reasoning and req.reasoning != "off":
        caps.append("reasoning")
    if req.response_format:
        caps.append("structured")
    if req.messages:
        for m in req.messages:
            if P._content_has_image(m.get("content")):
                caps.append("vision")
                break
    return caps


async def _resolve_image_urls(messages):
    out = []
    for m in messages:
        content = m.get("content")
        if not isinstance(content, list):
            out.append(m)
            continue
        new_blocks = []
        changed = False
        for b in content:
            if isinstance(b, dict) and b.get("type") == "image_url":
                iu = b.get("image_url")
                url = iu.get("url") if isinstance(iu, dict) else iu
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    try:
                        data_url = await fetch_image_as_data_url(url)
                    except ImageURLFetchError as e:
                        raise HTTPException(400, f"failed to fetch image url {url!r}: {e}")
                    new_blocks.append({"type": "image_url", "image_url": {"url": data_url}})
                    changed = True
                    continue
            new_blocks.append(b)
        if changed:
            new_m = dict(m)
            new_m["content"] = new_blocks
            out.append(new_m)
        else:
            out.append(m)
    return out


def _validate_structured(text: str, schema: dict):
    try:
        obj = json.loads(text)
    except Exception as e:
        raise ValueError(f"output is not JSON: {e}")
    Draft202012Validator(schema).validate(obj)
    return obj


# ─────────────────────────── routes ───────────────────────────


async def _chat_impl(req: ChatRequest, request: Request, *, accounting_agent: str | None = None):
    state = request.app.state
    ledger = state.ledger
    rtr = state.router
    router_pool = state.router_pool
    messages = _normalize_messages(req)
    if any(P._content_has_image(m.get("content")) for m in messages):
        messages = await _resolve_image_urls(messages)
    system_blocks = _system_blocks(req)
    prompt_text = "".join(
        (
            P._extract_text_blocks(m.get("content", ""))
            if isinstance(m.get("content"), list)
            else str(m.get("content", ""))
        )
        for m in messages
    )
    est = _est_tokens(messages, system_blocks, req.max_tokens)
    explicit_override = bool(req.provider)
    required_caps = _required_caps(req)

    if req.agent and not req.provider:
        pinned = AGENT_ROUTING.get(req.agent)
        if pinned and pinned in rtr.providers:
            req.provider = pinned
            explicit_override = True

    retries = 0
    router_decision: RouterDecision | None = None
    if req.auto_route and not req.provider:
        router_decision = await _classify_tier(req, req.auto_route, router_pool, prompt_text, ledger)
        if router_decision.tier == "HUGE":
            raise HTTPException(
                503,
                {
                    "error": "input exceeds 8000 tokens",
                    "hint": "Use the Summarizer Agent (V7, not yet implemented). "
                    "For now, chunk the input or set provider=g explicitly to try Gemini anyway.",
                    "router_decision": router_decision.model_dump(),
                },
            )
        tier_order = TIER_TO_ORDER[router_decision.tier]
        candidates = [p for p in tier_order if p in rtr.providers]
    else:
        candidates = rtr.candidates(req.provider) if req.provider else list(rtr.order)

    if req.provider and not candidates:
        raise HTTPException(
            400,
            f"unknown provider '{req.provider}'. Try one of: {list(rtr.providers)} or shortcuts {list(SHORTCUTS)}",
        )

    all_attempts: list[dict] = []

    if explicit_override and len(candidates) == 1:
        deadline = time.time() + 30
        while time.time() < deadline:
            name, _ = rtr.pick(est, candidates, required_caps=required_caps)
            if name is not None:
                break
            cd = rtr.state[candidates[0]].snapshot(LIMITS[candidates[0]])["cooldown_remaining"]
            if cd <= 0 or cd > 30:
                break
            await _asyncio.sleep(min(cd + 0.05, 5))

    for _ in range(len(candidates) + 1):
        name, atts = rtr.pick(est, candidates, required_caps=required_caps)
        all_attempts.extend(atts)
        if name is None:
            break
        provider = rtr.providers[name]
        t0 = time.time()
        rtr.state[name].record(0)
        try:
            if req.stream:

                async def gen():
                    try:
                        agg = []
                        async for chunk in provider.stream(
                            messages,
                            max_tokens=req.max_tokens,
                            temperature=req.temperature,
                            model=req.model,
                            tools=req.tools,
                            tool_choice=req.tool_choice,
                            reasoning=req.reasoning,
                            response_format=req.response_format,
                            system_blocks=system_blocks,
                            cache_system=bool(req.cache_system),
                        ):
                            agg.append(chunk)
                            if chunk.startswith("[[TOOL_CALL_DELTA]]"):
                                yield f"data: {json.dumps({'provider': name, 'tool_call_delta': chunk[len('[[TOOL_CALL_DELTA]] ') :]})}\n\n"
                            else:
                                yield f"data: {json.dumps({'provider': name, 'delta': chunk})}\n\n"
                        text = "".join(agg)
                        latency = int((time.time() - t0) * 1000)
                        ledger.log_call(
                            provider=name,
                            model=req.model or provider.model,
                            latency_ms=latency,
                            status="ok",
                            prompt_chars=len(prompt_text),
                            response_chars=len(text),
                            override=req.provider,
                            attempted=_attempts_str(all_attempts),
                            agent=accounting_agent,
                            session=req.session,
                            retries=retries,
                        )
                        yield f"data: {json.dumps({'done': True, 'provider': name})}\n\n"
                    except Exception:
                        logger.exception("Streaming upstream request failed (provider=%s)", name)
                        ledger.log_call(
                            provider=name,
                            model=req.model or provider.model,
                            status="error",
                            error=PUBLIC_UPSTREAM_ERROR,
                            latency_ms=int((time.time() - t0) * 1000),
                            prompt_chars=len(prompt_text),
                            override=req.provider,
                            attempted=_attempts_str(all_attempts),
                            agent=accounting_agent,
                            session=req.session,
                            retries=retries,
                        )
                        yield f"data: {json.dumps({'error': PUBLIC_UPSTREAM_ERROR})}\n\n"

                return StreamingResponse(gen(), media_type="text/event-stream")

            try:
                result = await provider.chat(
                    messages,
                    max_tokens=req.max_tokens,
                    temperature=req.temperature,
                    model=req.model,
                    tools=req.tools,
                    tool_choice=req.tool_choice,
                    reasoning=req.reasoning,
                    response_format=req.response_format,
                    system_blocks=system_blocks,
                    cache_system=bool(req.cache_system),
                )
            except (P.ProviderError, Exception) as transient:
                status = getattr(transient, "status", None)
                msg = str(transient).lower()
                retryable = (status is not None and 500 <= status < 600) or status == 408 or "timeout" in msg
                if not retryable:
                    raise
                logger.warning(
                    "Retrying transient upstream request failure (provider=%s)",
                    name,
                    exc_info=True,
                )
                await _asyncio.sleep(min(2.0, 0.5 * (2**retries)))
                retries += 1
                result = await provider.chat(
                    messages,
                    max_tokens=req.max_tokens,
                    temperature=req.temperature,
                    model=req.model,
                    tools=req.tools,
                    tool_choice=req.tool_choice,
                    reasoning=req.reasoning,
                    response_format=req.response_format,
                    system_blocks=system_blocks,
                    cache_system=bool(req.cache_system),
                )
            latency = int((time.time() - t0) * 1000)

            parsed = None
            if req.response_format and req.response_format.schema_ and not result["tool_calls"]:
                try:
                    parsed = _validate_structured(result["text"], req.response_format.schema_)
                except (ValueError, ValidationError) as ve:
                    fix_msgs = list(messages) + [
                        {"role": "assistant", "content": result["text"]},
                        {
                            "role": "user",
                            "content": f"Your previous reply did not match the required JSON schema: {ve}. Reply ONLY with valid JSON conforming to the schema.",
                        },
                    ]
                    result = await provider.chat(
                        fix_msgs,
                        max_tokens=req.max_tokens,
                        temperature=0,
                        model=req.model,
                        response_format=req.response_format,
                        system_blocks=system_blocks,
                        cache_system=bool(req.cache_system),
                    )
                    try:
                        parsed = _validate_structured(result["text"], req.response_format.schema_)
                    except (ValueError, ValidationError) as ve2:
                        raise HTTPException(503, f"structured output failed validation: {ve2}")

            tokens = (result["input_tokens"] or 0) + (result["output_tokens"] or 0)
            rtr.state[name].tokens_today += tokens
            rtr.state[name].tokens_minute.append((time.time(), tokens))
            if router_decision is not None:
                router_decision.chosen_worker_provider = name
                router_decision.chosen_worker_model = result["model"]
            ledger.log_call(
                provider=name,
                model=result["model"],
                input_tokens=result["input_tokens"],
                output_tokens=result["output_tokens"],
                cache_create_tokens=result["cache_creation_input_tokens"],
                cache_read_tokens=result["cache_read_input_tokens"],
                latency_ms=latency,
                status="ok",
                prompt_chars=len(prompt_text),
                response_chars=len(result["text"]),
                override=req.provider,
                attempted=_attempts_str(all_attempts),
                tool_calls=len(result["tool_calls"]),
                reasoning_applied=result["reasoning_applied"],
                tool_dialect=result["tool_call_dialect"],
                call_role="worker",
                router_decision=router_decision.tier if router_decision else None,
                agent=accounting_agent,
                session=req.session,
                retries=retries,
            )
            return ChatResponse(
                provider=name,
                model=result["model"],
                text=result["text"],
                tool_calls=[ToolCall(**tc) for tc in result["tool_calls"]],
                stop_reason=result["stop_reason"],
                input_tokens=result["input_tokens"],
                output_tokens=result["output_tokens"],
                cache_creation_input_tokens=result["cache_creation_input_tokens"],
                cache_read_input_tokens=result["cache_read_input_tokens"],
                latency_ms=latency,
                tool_call_dialect=result["tool_call_dialect"],
                reasoning_applied=result["reasoning_applied"],
                parsed=parsed,
                attempted=all_attempts,
                router_decision=router_decision,
                retries=retries,
            ).model_dump()
        except P.ProviderError as e:
            logger.exception("Upstream provider request failed (provider=%s)", name)
            secs, reason = _backoff_for(e, has_model_override=bool(req.model))
            if secs > 0:
                rtr.state[name].mark_unavailable(secs, reason)
            ledger.log_call(
                provider=name,
                model=req.model or provider.model,
                status="error",
                error=PUBLIC_UPSTREAM_ERROR,
                latency_ms=int((time.time() - t0) * 1000),
                prompt_chars=len(prompt_text),
                override=req.provider,
                attempted=_attempts_str(all_attempts),
                agent=accounting_agent,
                session=req.session,
                retries=retries,
            )
            all_attempts.append({"provider": name, "reason": PUBLIC_UPSTREAM_ERROR})
            if explicit_override or not getattr(e, "retryable", True):
                raise HTTPException(502, PUBLIC_UPSTREAM_ERROR)
            candidates = [c for c in candidates if c != name]
            continue
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Unexpected upstream request failure (provider=%s)", name)
            secs, reason = _backoff_for(e, has_model_override=bool(req.model))
            if secs > 0:
                rtr.state[name].mark_unavailable(secs, reason)
            ledger.log_call(
                provider=name,
                model=req.model or provider.model,
                status="error",
                error=PUBLIC_UPSTREAM_ERROR,
                latency_ms=int((time.time() - t0) * 1000),
                prompt_chars=len(prompt_text),
                override=req.provider,
                attempted=_attempts_str(all_attempts),
                agent=accounting_agent,
                session=req.session,
                retries=retries,
            )
            all_attempts.append({"provider": name, "reason": PUBLIC_UPSTREAM_ERROR})
            if explicit_override:
                raise HTTPException(502, PUBLIC_UPSTREAM_ERROR)
            candidates = [c for c in candidates if c != name]
            continue

    raise HTTPException(503, PUBLIC_UPSTREAM_ERROR)


@router.post("/v1/chat")
async def chat(
    req: ChatRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    principal = authorize_tool_request(
        request,
        authorization,
        tool="llm.chat",
        expected_models={req.model},
    )
    accounting_agent = principal.slot if principal.kind == "slot" else req.agent
    return await _chat_impl(req, request, accounting_agent=accounting_agent)


@router.post("/v1/chat/batch")
async def chat_batch(
    req: BatchChatRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    principal = authorize_tool_request(
        request,
        authorization,
        tool="llm.chat.batch",
        expected_models={call.model for call in req.calls},
    )
    sem = _asyncio.Semaphore(max(1, req.max_concurrency))

    async def _one(call: ChatRequest):
        async with sem:
            try:
                accounting_agent = principal.slot if principal.kind == "slot" else call.agent
                return await _chat_impl(call, request, accounting_agent=accounting_agent)
            except HTTPException as he:
                return {"error": str(he.detail), "status_code": he.status_code}
            except Exception:
                logger.exception("Unexpected batch chat failure")
                return {"error": PUBLIC_UPSTREAM_ERROR, "status_code": 500}

    results = await _asyncio.gather(*[_one(c) for c in req.calls])
    return {"results": results}


@router.post("/v1/vision")
async def vision(
    req: VisionRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    principal = authorize_tool_request(
        request,
        authorization,
        tool="llm.vision",
        expected_models={req.model},
    )
    content: list[dict[str, Any]] = [{"type": "text", "text": req.prompt}]
    content.append({"type": "image_url", "image_url": {"url": req.image}})
    inner = ChatRequest(
        messages=[{"role": "user", "content": content}],
        system=req.system,
        provider=req.provider,
        model=req.model,
        max_tokens=req.max_tokens,
        temperature=req.temperature,
        response_format=(
            ResponseFormat(type="json_schema", schema=req.schema_, name=req.schema_name, strict=True)
            if req.schema_
            else None
        ),
        agent=req.agent,
        session=req.session,
    )
    accounting_agent = principal.slot if principal.kind == "slot" else req.agent
    return await _chat_impl(inner, request, accounting_agent=accounting_agent)


@router.post("/v1/embed")
async def embed(
    req: EmbedRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
):
    principal = authorize_tool_request(request, authorization, tool="llm.embed")
    accounting_agent = principal.slot if principal.kind == "slot" else None
    from glc import embedders as E

    state = request.app.state
    embedders = state.embedders
    if not embedders:
        raise HTTPException(503, "no embedding providers configured")
    if len(req.text) > E.MAX_INPUT_CHARS:
        raise HTTPException(
            413,
            f"text is {len(req.text)} chars; embed input is capped at "
            f"{E.MAX_INPUT_CHARS} chars (~{E.MAX_INPUT_CHARS // 4} tokens). Chunk and re-embed.",
        )
    t0 = time.time()
    try:
        name, result, attempts, latency = await E.embed_with_failover(
            embedders,
            req.text,
            req.task_type,
            explicit=req.provider,
        )
    except E.EmbedderError as e:
        latency = int((time.time() - t0) * 1000)
        logger.exception("Embedding provider request failed (provider=%s)", req.provider or "(any)")
        request.app.state.ledger.log_call(
            provider=req.provider or "(any)",
            model="(none)",
            status="error",
            error=PUBLIC_UPSTREAM_ERROR,
            latency_ms=latency,
            prompt_chars=len(req.text),
            override=req.provider,
            call_role="embed",
            agent=accounting_agent,
        )
        if req.provider:
            if e.status == 429:
                raise HTTPException(429, PUBLIC_UPSTREAM_ERROR)
            if e.status == 400:
                raise HTTPException(400, PUBLIC_UPSTREAM_ERROR)
            raise HTTPException(502, PUBLIC_UPSTREAM_ERROR)
        raise HTTPException(503, PUBLIC_UPSTREAM_ERROR)

    public_attempts = _public_attempts(attempts)
    request.app.state.ledger.log_call(
        provider=name,
        model=result["model"],
        status="ok",
        latency_ms=latency,
        prompt_chars=len(req.text),
        override=req.provider,
        attempted=_attempts_str(public_attempts),
        call_role="embed",
        embed_dim=result["dim"],
        agent=accounting_agent,
    )
    return EmbedResponse(
        provider=name,
        model=result["model"],
        embedding=result["embedding"],
        dim=result["dim"],
        latency_ms=latency,
        attempted=public_attempts,
    ).model_dump()


@router.get("/v1/embedders", dependencies=[Depends(require_install_token)])
async def list_embedders(request: Request):
    from glc import embedders as E

    state = request.app.state
    return {
        "order": state.embed_order,
        "models": {e.name: e.model for e in state.embedders},
        "fixed_dim": E.EMBED_DIM,
        "max_input_chars": E.MAX_INPUT_CHARS,
        "backoff_steps_s": E.BACKOFF_STEPS,
        "live": {e.name: e.state.snapshot() for e in state.embedders},
        "today": request.app.state.ledger.aggregate(call_role="embed"),
    }


@router.get("/v1/cost/by_agent", dependencies=[Depends(require_install_token)])
async def cost_by_agent(request: Request, session: str | None = None, agent: str | None = None):
    from glc import pricing as _pricing

    raw = request.app.state.ledger.by_agent(session=session)
    if agent:
        raw = {agent: raw.get(agent, [])}
    out: dict[str, list[dict]] = {}
    for ag, rows in raw.items():
        out[ag] = []
        for r in rows:
            r2 = dict(r)
            r2["dollars"] = _pricing.estimate_usd(r["provider"], r.get("in_tok") or 0, r.get("out_tok") or 0)
            out[ag].append(r2)
    return out


@router.get("/v1/providers", dependencies=[Depends(require_install_token)])
async def list_providers(request: Request):
    r = request.app.state.router
    return {
        "order": r.order,
        "providers": list(r.providers.keys()),
        "shortcuts": SHORTCUTS,
        "limits": LIMITS,
        "models": {n: p.model for n, p in r.providers.items()},
    }


@router.get("/v1/capabilities", dependencies=[Depends(require_install_token)])
async def capabilities(request: Request):
    r = request.app.state.router
    out = {}
    for name, p in r.providers.items():
        caps = dict(getattr(p, "capabilities", {}))
        caps = P.model_capabilities(name, p.model, caps)
        caps["model"] = p.model
        caps.update(
            {
                "max_ctx": LIMITS[name]["max_ctx"],
                "rpm": LIMITS[name]["rpm"],
                "rpd": LIMITS[name]["rpd"],
            }
        )
        out[name] = caps
    return out


@router.get("/v1/status", dependencies=[Depends(require_install_token)])
async def status(request: Request):
    r = request.app.state.router
    return {
        "order": r.order,
        "live": r.all_status(),
        "today": request.app.state.ledger.aggregate(call_role="worker"),
        "limits": LIMITS,
    }


@router.get("/v1/routers", dependencies=[Depends(require_install_token)])
async def routers(request: Request):
    rp = request.app.state.router_pool
    return {
        "order": rp.order,
        "providers": list(rp.providers.keys()),
        "models": {n: p.model for n, p in rp.providers.items()},
        "live": rp.all_status(),
        "today": request.app.state.ledger.aggregate(call_role="router"),
        "limits": {k: LIMITS[k] for k in rp.providers},
        "tier_to_order": TIER_TO_ORDER,
    }


@router.get("/v1/calls", dependencies=[Depends(require_install_token)])
async def calls(
    request: Request,
    limit: int = 100,
    provider: str | None = None,
    status: str | None = None,
):
    rows = request.app.state.ledger.recent(limit=limit, provider=provider, status=status)
    for row in rows:
        if row.get("error"):
            row["error"] = PUBLIC_UPSTREAM_ERROR
        if row.get("attempted"):
            row["attempted"] = _sanitize_persisted_attempted(row["attempted"])
    return rows
