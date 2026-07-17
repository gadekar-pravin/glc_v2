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

## Leak 2 — In-process code could erase the audit history

**Invariant broken.** Invariant 7: every security-relevant action must be recorded in an append-only,
tamper-evident history.

**Attacker role.** Code executing inside the gateway process with the gateway's filesystem identity.
Before slot isolation, this included every in-process channel adapter.

**Finding.** The audit API exposed only `append()`, but the SQLite database had no database-level
write protection and no integrity chain. On Modal, `GLC_CONFIG_DIR` and `GLC_AUDIT_DB` both resolve
to `/data/glc`, so this statement opened the real audit file and silently removed every row:

```python
import os, sqlite3
p = os.path.join(os.getenv("GLC_CONFIG_DIR", "."), "audit.sqlite")
sqlite3.connect(p).execute("DELETE FROM audit_log")
```

The safe pre-fix reproduction used an isolated temporary database and reported
`rows_before=1`, `deleted_rows=1`, `rows_after=0`, and zero protective triggers.

**Fix.** Audit schema v2 adds `BEFORE UPDATE` and `BEFORE DELETE` triggers that abort mutation with
`audit_log is append-only`. Every row now stores the previous entry hash and a SHA-256 hash over its
ID, all stored audit fields, and that previous hash. Appends take a SQLite immediate write lock,
calculate and insert the complete row atomically, and commit before returning. Startup validates the
schema, both triggers, and the complete chain; any mismatch raises `AuditIntegrityError` and prevents
the gateway from serving traffic.

Existing schema-v1 databases migrate transactionally. The migration preserves row IDs, payloads,
timestamps, ordering, and the prior AUTOINCREMENT high-water mark while backfilling the chain. Rows
erased before this fix cannot be recovered. The existing `glc-data` volume remains mounted only on
the gateway Modal function; isolated adapter functions have no access to it.

**Post-fix evidence.** The same temporary reproduction now reports `delete_blocked=True`, error
`audit_log is append-only`, `rows_before=1`, `rows_after=1`, and `chain_valid=True`. Focused tests
also cover direct updates, v1 migration, concurrent appends, content and link tampering, missing
triggers, unsupported schemas, and gateway-only volume access.

The final gateway-spec Modal probe targeted the deployed `/data/glc/audit.sqlite` and reported
`schema_version=2`, `target_matches_audit_env=true`, `delete_blocked=true`,
`rows_before=1`, `rows_after=1`, and `chain_valid=true`. The authenticated live health check
continued to return HTTP 200 with `{"ok": true, "port": 8111}`.

## Leak 3 — Adapter code could grant itself owner trust

**Invariant broken.** Every action must be checked against the actual user, tenant, and final
arguments. An adapter-controlled trust claim must never become gateway authority.

**Attacker role.** An attacker controlling a channel adapter or one of its dependencies.

**Finding.** The pairing store exposed `force_pair_owner()` to every adapter in the monolithic
process. The supplied reproduction created an owner record and the normal classifier immediately
returned `owner_paired` for the attacker. After initial container separation, the gateway still
trusted the adapter-supplied `trust_level`, so a slot could claim the same authority without even
mutating the gateway database.

**Fix.** Adapters now emit an untrusted `ChannelIngress` containing provider facts only. For each
WebSocket message the gateway replaces the claimed channel with the authenticated slot, derives
trust from its own pairing database, refreshes the owner list, and constructs the internal
`ChannelMessage` before allowlist, rate-limit, audit, or agent processing. Legacy `channel` and
`trust_level` fields remain accepted but are ignored. `force_pair_owner()` was removed; owners are
provisioned only through the install-token-authenticated pair and confirm endpoints. Adapter images
exclude the security package and pairing Volume, and gateway webhook routes no longer instantiate
adapters in-process in local or production mode.

**Post-fix evidence.** Regression tests prove a forged owner claim is dropped, a legitimately paired
owner succeeds even when claiming `untrusted`, channel claims normalize to the authenticated slot,
and pairings become visible on an existing WebSocket without reconnecting. Static image tests prove
all 15 adapters avoid pairing/trust imports and the Telegram slot excludes pairing code and storage.
The deployed Telegram probe reported `pairing_api_absent=true` and
`forged_owner_rejected=true`; every LLM provider key was absent from the slot. The authenticated
gateway health check returned `{"ok":true,"port":8111}`. The persisted live pairing database had no
existing owner record, so owner success was verified by the control-plane-backed regression without
creating a synthetic production owner.

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
