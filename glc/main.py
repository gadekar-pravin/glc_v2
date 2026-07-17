"""FastAPI app for glc_v1. Port 8111 by default. V9 routes are mounted
as-is (S9 Browser / S10 Computer-Use clients work unchanged); the new
S11 surfaces (transcribe, speak, channels WS, control) sit alongside.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

ROOT = Path(__file__).parent
load_dotenv(ROOT.parent / ".env")  # repo .env, if present

from glc import db  # noqa: E402
from glc import embedders as E  # noqa: E402
from glc import providers as P  # noqa: E402
from glc.audit import init_store as init_audit  # noqa: E402
from glc.cache import GeminiCache  # noqa: E402
from glc.config import get_or_create_install_token  # noqa: E402
from glc.ledger import SignedLedgerWriter  # noqa: E402
from glc.policy import ProcessPolicyClient  # noqa: E402
from glc.routes import channels as channels_route  # noqa: E402
from glc.routes import chat as chat_route  # noqa: E402
from glc.routes import control as control_route  # noqa: E402
from glc.routes import creds as creds_route  # noqa: E402
from glc.routes import speak as speak_route  # noqa: E402
from glc.routes import transcribe as transcribe_route  # noqa: E402
from glc.routing import Router, RouterPool  # noqa: E402

PORT = int(os.getenv("GLC_PORT", "8111"))


def _install_sighup_reload(policy_client: ProcessPolicyClient) -> None:
    """Hot-reload policy.yaml on SIGHUP. Windows lacks SIGHUP so this is
    a no-op there."""
    if not hasattr(signal, "SIGHUP"):
        return

    loop = asyncio.get_running_loop()
    reload_scheduled = False
    reload_task: asyncio.Task[None] | None = None

    async def _reload() -> None:
        nonlocal reload_scheduled, reload_task
        try:
            reloaded = await asyncio.to_thread(policy_client.reload)
            if reloaded:
                print("[glc] policy.yaml reloaded via SIGHUP")
            else:
                print("[glc] SIGHUP reload failed: policy worker unavailable")
        finally:
            reload_scheduled = False
            reload_task = None

    def _schedule_reload() -> None:
        nonlocal reload_scheduled, reload_task
        if reload_scheduled:
            return
        reload_scheduled = True
        reload_task = asyncio.create_task(_reload())

    def _handler(signum, frame):  # noqa: ARG001
        loop.call_soon_threadsafe(_schedule_reload)

    try:
        signal.signal(signal.SIGHUP, _handler)
    except ValueError:
        # signal() only works on the main thread; tests using TestClient
        # spawn lifespan from a worker thread. Silent skip is correct here.
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    policy_client = ProcessPolicyClient()
    policy_client.start()
    print(f"[glc] policy worker ready pid={policy_client.worker_pid}")
    app.state.policy_client = policy_client
    try:
        db.init()
        init_audit()
        get_or_create_install_token(production=bool(getattr(app.state, "production", False)))
        ledger = SignedLedgerWriter.from_environment(production=bool(getattr(app.state, "production", False)))
        ledger.init()
        app.state.ledger = ledger
        _install_sighup_reload(policy_client)
        app.state.cache = GeminiCache(ttl_seconds=300)
        app.state.providers = P.build_providers(app.state.cache)
        app.state.router = Router(app.state.providers, chat_route.ORDER)
        app.state.router_providers = P.build_router_providers()
        app.state.router_pool = RouterPool(app.state.router_providers, chat_route.ROUTER_ORDER)
        app.state.embedders, app.state.embed_order = E.build_embedders()
        app.state.started_at = time.time()
        app.state.registered_channels = []
        yield
    finally:
        policy_client.close()


def _production_mode() -> bool:
    return os.getenv("GLC_ENV", "").strip().lower() == "production"


def create_app(*, production: bool | None = None) -> FastAPI:
    """Build the gateway, applying the production perimeter when enabled."""
    is_production = _production_mode() if production is None else production
    application = FastAPI(
        title="GLC v1 — Gateway for LLMs and Channels",
        lifespan=lifespan,
        openapi_url=None if is_production else "/openapi.json",
        docs_url=None if is_production else "/docs",
        redoc_url=None if is_production else "/redoc",
    )
    application.state.production = is_production

    application.include_router(chat_route.router)
    application.include_router(transcribe_route.router)
    application.include_router(speak_route.router)
    application.include_router(control_route.router)
    application.include_router(channels_route.router)
    application.include_router(creds_route.router)

    if is_production:

        @application.middleware("http")
        async def require_gateway_token(request: Request, call_next):
            scoped_paths = {
                "/v1/chat",
                "/v1/chat/batch",
                "/v1/vision",
                "/v1/embed",
                "/v1/transcribe",
                "/v1/speak",
                "/v1/creds/issue",
            }
            if request.url.path in scoped_paths:
                authorization = request.headers.get("Authorization")
                if not authorization or not authorization.startswith("Bearer "):
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "missing bearer token (Authorization: Bearer <install_token>)"},
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                if not authorization.removeprefix("Bearer ").strip():
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "missing bearer token (Authorization: Bearer <install_token>)"},
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return await call_next(request)
            authorization = request.headers.get("Authorization")
            if not authorization or not authorization.startswith("Bearer "):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "missing bearer token (Authorization: Bearer <install_token>)"},
                    headers={"WWW-Authenticate": "Bearer"},
                )

            presented = authorization.removeprefix("Bearer ").strip()
            if not presented:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "missing bearer token (Authorization: Bearer <install_token>)"},
                    headers={"WWW-Authenticate": "Bearer"},
                )

            expected = get_or_create_install_token(production=is_production)
            if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
                return JSONResponse(status_code=403, content={"detail": "install token mismatch"})

            return await call_next(request)

    @application.get("/", response_class=HTMLResponse)
    async def index() -> str:
        docs_hint = "" if is_production else "<p>Open <code>/docs</code> for the OpenAPI explorer.</p>"
        return (
            "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
            "<h1>GLC v1</h1>"
            "<p>Gateway for LLMs and Channels — Session 11 scaffold.</p>"
            f"{docs_hint}"
            "<p>Channel adapters connect over <code>WS /v1/channels/&lt;name&gt;</code>."
            " V9 callers should point at this port unchanged: chat, vision, embed,"
            " batch, cost-by-agent, providers, capabilities, status, calls."
            "</p>"
            "</body></html>"
        )

    @application.get("/healthz")
    async def healthz():
        policy_client = getattr(application.state, "policy_client", None)
        if policy_client is None or not await asyncio.to_thread(policy_client.ping):
            return JSONResponse(
                status_code=503,
                content={"ok": False, "port": PORT, "policy": "unavailable"},
            )
        ledger = getattr(application.state, "ledger", None)
        if ledger is None or not await asyncio.to_thread(ledger.integrity_ok):
            return JSONResponse(
                status_code=503,
                content={"ok": False, "port": PORT, "ledger": "unavailable"},
            )
        return {"ok": True, "port": PORT}

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)
