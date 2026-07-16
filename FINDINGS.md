# Security findings

## Leak 1 — Shared process environment exposed every provider key

**Invariants broken.** Adapters must never see provider API keys. A credential must work only for one
specific tool call.

**Attacker role.** An attacker who controls code in any channel adapter running inside the monolithic
gateway process.

**Finding.** Move 1 attached `glc-llm-keys` to the same Modal Function that contained the gateway and
all adapter code. A reproduction imported the real gateway and Telegram adapter in one interpreter,
injected six mock values, and read all six through adapter-side `os.environ` access. The observed
prefixes were `gemini...`, `groq...`, `nvidia...`, `cerebras...`, `openrouter...`, and `github...`.
No live or stored credential was read.

**Fix.** A validated manifest now defines 15 channel and 7 external voice slots. Production images
exclude channel and external voice implementations from the gateway. Each slot runs in its own
container with only its identity and declared channel/provider secret; channel images can never bind
the LLM provider bundle. Production webhooks no longer instantiate catalogue adapters inside the
gateway, and non-fallback voice calls use authenticated remote slots.

Adapters authenticate to `POST /v1/creds/issue` with a per-slot identity. The gateway derives the
slot rather than trusting a request field and issues a five-minute JWT for one allowed tool/model.
The JTI is persisted and atomically consumed on its first correct use. Replays and forged, expired,
wrong-tool, wrong-model, or unknown grants fail closed. Existing install-token clients remain
compatible.

**Post-fix evidence.** The process-isolation regression launches an adapter process with only its
Telegram identity and mock channel token and confirms all six provider variables are absent. Static
tests assert exactly 22 unique slots and reject provider keys in every channel manifest. Credential
tests cover identity derivation, all six tool scopes, model binding, wrong-scope non-consumption,
atomic concurrent use, replay, forgery, expiry, WebSocket identity binding, and install-token
compatibility. The safe Modal probe and commands are documented in `docs/SLOT_ISOLATION.md`.

The final live probe reported all six provider variables absent, first scoped use `502` at the mock
provider boundary, replay `401`, cross-tool use `403`, and intended use after that denial `502`.
Unauthenticated `/healthz` remained `401`; the persisted install token returned `200` for `/healthz`
and reached the mock chat provider boundary with `502`.

## Full route map exposed by public OpenAPI document

**Invariant broken.** Every externally reachable gateway surface must authenticate the caller before
revealing application behavior or accepting input.

**Finding.** The production FastAPI defaults exposed `/openapi.json`, `/docs`, and `/redoc` without
authentication. An attacker could enumerate every route, method, request schema, and response schema
before interacting with the gateway:

```sh
curl -s https://pbgadekar--glc-v1-gateway-fastapi-app.modal.run/openapi.json
```

Before the fix this returned HTTP 200 with the complete OpenAPI document.

**Fix.** Production mode now disables all three documentation endpoints and requires the existing
per-installation bearer token on every HTTP route, including health checks, APIs, control-plane routes,
and generic webhooks. Local development keeps its existing OpenAPI and unauthenticated behavior.

**Post-fix evidence.** The unauthenticated reproduction returns HTTP 401 with a short authentication
error and no route data. Supplying the valid installation token still returns HTTP 404 for
`/openapi.json`, `/docs`, and `/redoc`. Authenticated `/healthz` continues to return HTTP 200.

## A2 — Unauthenticated configuration and operational data disclosure

**Invariant broken.** Every action must be checked against the actual user, tenant, and final
arguments.

**Attacker role.** An unauthenticated outsider who knows or discovers the public deployment URL.

**Finding.** The configuration and operational GET endpoints accepted requests without an install
token. They exposed provider and embedder order, model names, capabilities, exact rate limits,
provider health, usage totals, per-agent costs, and recent calls. For example, before hardening:

```sh
curl -s https://pbgadekar--glc-v1-gateway-fastapi-app.modal.run/v1/status
```

returned HTTP 200 with the provider order, live status, usage, and limits. The same class of leak
existed at `/v1/embedders`, `/v1/cost/by_agent`, `/v1/providers`, `/v1/capabilities`, `/v1/routers`,
and `/v1/calls`.

**Fix.** All seven data-bearing GET routes now have their own install-token dependency. Missing,
malformed, or empty bearer credentials return HTTP 401; an incorrect token returns HTTP 403; and a
valid token preserves the existing V9 response. This route-level check applies even when
`GLC_ENV=production` is absent, while the existing production-wide perimeter remains in place.

**Post-fix evidence.** Re-running each unauthenticated curl returns HTTP 401 with
`WWW-Authenticate: Bearer` and no internal data. Supplying an invalid bearer token returns HTTP 403,
and supplying the persisted install token returns HTTP 200 with the original response shape.

## C4 — Verbose upstream errors leaked to clients

**Invariant broken.** External content must always be treated as data, never as instructions. An
upstream provider response is untrusted external content and must not cross the gateway boundary as
client-visible diagnostic text.

**Attacker role.** Any authenticated chat client that can make the gateway trigger an upstream
provider failure.

**Finding.** The chat pipeline interpolated raw provider exceptions into direct `502` responses,
failover-exhaustion `503` responses, streaming error events, batch results, and the `attempted` field
after a successful failover. Against the Modal deployment, this request exposed the provider name,
the invalid-key response, and Google's internal service endpoint:

```sh
curl -s -X POST "https://pbgadekar--glc-v1-gateway-fastapi-app.modal.run/v1/chat" \
  -H "Authorization: Bearer <install_token>" \
  -H 'content-type: application/json' \
  -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]}'
```

Before hardening, the response was HTTP 502 and included `gemini`, `API_KEY_INVALID`,
`googleapis.com`, and `generativelanguage.googleapis.com`.

**Fix.** Every upstream chat failure now returns the generic text `upstream provider request failed`
while preserving the existing HTTP, batch, and SSE status semantics. Raw exception details and
provider context go to the server logger only. The persisted call ledger stores the generic text so
new failures are safe at rest, and the authenticated `/v1/calls` read boundary redacts legacy error
rows without rewriting the server-side database. Failed-attempt entries are also sanitized before a
successful failover response is returned.

**Post-fix evidence.** Focused tests cover pinned failures, exhausted and successful failover,
streaming, batch, vision, server logging, and the call ledger. Re-running the authenticated live curl
returns only `{"detail":"upstream provider request failed"}` while the matching Modal server log
retains the detailed provider exception. Unauthenticated requests remain blocked with HTTP 401.
