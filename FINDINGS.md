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

## Leak 4 — In-process adapter code could read the install token

**Invariant broken.** The control plane must remain out-of-band. An adapter must never receive the
credential that authorizes control-plane actions.

**Attacker role.** An attacker controlling a channel adapter or one of its in-process dependencies.

**Finding.** The production gateway generated its active install token at
`GLC_CONFIG_DIR/install_token`. Because `GLC_CONFIG_DIR=/data/glc`, any code in the monolithic
gateway process could open the file and reuse the value against the control plane:

```python
import os

p = os.path.join(os.getenv("GLC_CONFIG_DIR", "."), "install_token")
print(open(p).read()[:6] + "...")
```

The safe pre-fix reproduction used an isolated temporary directory, printed no token characters, and
reported `file_created=true`, `arbitrary_in_process_read_matches=true`, and `token_length=43`.

**Fix.** Production now requires `GLC_INSTALL_TOKEN`, injected from the gateway-only Modal Secret
`glc-install-token`. The environment value takes precedence without reading or creating a token file;
an absent or empty production Secret fails startup even when a legacy file exists. Local development
retains its file-backed `uv run glc token` workflow. The Secret is attached only to `fastapi_app`.
Adapter functions have neither the Secret nor the gateway Volume, their images exclude `glc.config`,
and the slot-manifest loader rejects `GLC_INSTALL_TOKEN` in every slot declaration.

**Post-fix evidence.** Regression tests prove production never falls back to the legacy file, local
token compatibility remains intact, and the Modal function specifications bind the Secret only to
the gateway. The isolated adapter-process test reports the install-token environment variable absent
and the candidate token file unreadable without exposing a secret value.

The live token was rotated into `glc-install-token`, with the operator copy retained in macOS
Keychain. After deployment, authenticated `/healthz` returned HTTP 200 and an invalid token returned
HTTP 403. The legacy `glc/install_token` was then removed from `glc-data`; a gateway-container probe
reported `active_token_env_present=true`, `legacy_file_exists=false`,
`legacy_file_readable=false`, and `original_file_read_failed=true`. Authenticated `/healthz` remained
HTTP 200 after cleanup. The deployed Telegram probe reported `install_token_env_absent=true` and
`install_token_file_readable=false`; all six provider variables were absent, the forged-owner attempt
was rejected, scoped use reached the mock-provider boundary with 502, replay returned 401,
cross-tool use returned 403, and intended use after denial again reached the boundary with 502.

## Leak 5 — In-process code could disable the policy engine

**Invariant broken.** Policy authorization must run outside the mutable process context of the code
it constrains. A policy check is not an enforcement boundary when in-process code can replace it.

**Attacker role.** Code executing inside the gateway interpreter. Before slot isolation, this
included every in-process channel adapter; the supplied assignment reproduction deliberately models
that capability.

**Finding.** The gateway exposed policy evaluation as a mutable module-level Python function. The
assignment snippet replaced that function with an unconditional allow verdict for every later caller
that resolved the module attribute:

```python
import glc.policy.engine as e
from glc.policy.schemas import PolicyVerdict

e.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pwn")
```

The safe pre-fix reproduction used an isolated temporary configuration. The same untrusted call was
first denied with `untrusted sender cannot dispatch any tool`, then returned
`{"action":"allow","reason":"pwn"}` after the rebind.

**Fix.** `PolicyEngine` is now a pure evaluator used only by a policy worker launched as a clean
`python -m glc.policy.worker` child interpreter. The gateway's lifespan owns a
`ProcessPolicyClient` and exchanges request-ID-bound JSON lines over private stdin/stdout pipes. The
worker loads and reloads `policy.yaml` itself, receives no provider keys, install token, signing key,
or slot identities, and reserves stdout for the validated protocol. `SIGHUP` reloads are forwarded
to the worker.

Startup fails if the child cannot prove readiness or reports a sensitive environment variable.
After startup, a crash, timeout, broken pipe, malformed response, mismatched request ID, worker
error, or invalid `PolicyVerdict` permanently marks the client unhealthy and returns a deterministic
deny verdict. `/healthz` reports HTTP 503 until the gateway restarts. The removed module-level
singleton and evaluation functions are not used by production code; assigning an `evaluate`
attribute in the gateway interpreter therefore cannot change the separately imported worker.

**Post-fix evidence.** The regression patches both `glc.policy.engine.evaluate` and
`PolicyEngine.evaluate` in the parent before the child starts, verifies the worker has a different
PID, and observes the untrusted call remain denied. Rebinding again after startup also leaves the
worker verdict unchanged. Focused tests cover reload, malformed-policy deny fallback, 32 concurrent
evaluations, secret stripping, graceful shutdown, child death, protocol failure, timeout, HTTP 503
readiness, and a static ban on production imports of the in-process evaluator.

This assignment-scoped boundary protects evaluator code and state from the supplied monkey-patch. It
does not claim to withstand arbitrary gateway code that patches the IPC client or bypasses policy
entirely; that stronger threat model requires policy authorization and protected action dispatch to
move together into a separate broker.

## A3 / Leak 6 — Adapter containers had unrestricted outbound network access

**Invariant broken.** An untrusted component must have only the network authority its declared role
requires. Container separation is not an egress boundary when compromised code can connect to any
public destination.

**Attacker role.** An attacker controlling a channel adapter or one of its dependencies.

**Finding.** The gateway is intentionally a trusted Modal Function that needs provider access, but
the separated Telegram adapter and its security probe were also deployed as Modal Functions. Modal
Functions have no outbound-domain control, and `modal_telegram.py` contained no network allowlist.
The live gateway logs independently proved the deployment could reach the public internet: on
2026-07-17, the mock Gemini request reached `generativelanguage.googleapis.com` and received the
upstream `API_KEY_INVALID` response. An owned adapter Function could therefore send data to an
arbitrary attacker-controlled TLS endpoint just as easily.

**Fix.** Telegram adapter code now runs only as the entrypoint of a named Modal Sandbox. Its
`outbound_domain_allowlist` contains exactly `api.telegram.org` and the hostname dynamically
discovered from the deployed gateway URL. The Sandbox receives only the Telegram channel token and
slot identity, exposes no inbound port, and mounts no Volume. The two Modal Functions left in the
adapter app are trusted, secretless orchestration functions: one reconciles the named Sandbox every
five minutes across Modal's 24-hour Sandbox lifetime, and one launches a short-lived proof Sandbox.

The slot manifest now carries an explicit `egress_domains` contract. Launch fails closed for an
empty declaration, a URL or path, a port, an IP literal, malformed DNS, or any wildcard.
The exact gateway hostname is validated and appended centrally, so future launchers cannot silently
fall back to unrestricted network access or a broad `*.modal.run` rule.

**Post-fix evidence.** The local regression suite proves the supervisor Functions bind no Secrets or
Volumes, the Sandbox receives only its two slot Secrets, its allowlist and resource limits are
exact, and running, expired, and concurrent named-Sandbox lifecycle paths behave correctly. The
short-lived runtime test proves allowed and denied network outcomes without using the internet.

The Telegram-only deployment on 2026-07-17 started named Sandbox
`sb-CJScffdYiJUaRjAZWCTDM5`; two reconciliations returned that same running ID. The final clean-commit
probe Sandbox `sb-Rr9L6B5kXI4cTGMv6rAshm` reported the exact allowlist
`["api.telegram.org", "pbgadekar--glc-v1-gateway-fastapi-app.modal.run"]`, reached Telegram and the
gateway, and reported `non_allowlisted_domain_unreachable=true`. Modal's system stream separately recorded
`blocking all outbound connections to example.com (not on allow-list)` at 09:55:22 IST. The same
proof reported every provider key absent, no install token file or environment value, no ledger
signing key/package/API, no pairing mutation API, forged-owner rejection, first/intended chat
statuses 502 under mock keys, replay 401, and cross-tool denial 403. An independent authenticated
gateway check returned HTTP 200 with `{"ok": true, "port": 8111}`.

## Leak 10 — In-process code could poison the cost ledger

**Invariants broken.** Every run must have hard limits on time, tokens, tool calls, and cost. Every
action must also be checked against the actual user, tenant, and final arguments.

**Attacker role.** Code executing inside the monolithic gateway interpreter. Before slot isolation,
this included every channel adapter and its dependencies.

**Finding.** `glc.db.log_call()` accepted arbitrary fields and inserted them directly into the active
cost ledger. The assignment reproduction, run against an isolated temporary database, created a
trusted-looking row with `agent="victim"` and `input_tokens=999999999`:

```python
import glc.db

glc.db.log_call(
    provider="gemini",
    model="x",
    input_tokens=999_999_999,
    agent="victim",
    status="ok",
)
```

**Fix.** The module-level write API was removed. The gateway lifespan now owns a strict
`SignedLedgerWriter`; it validates bounded accounting fields and signs a canonical schema-v2 record
with HMAC-SHA256 before insertion. Each signature binds a unique event ID, timestamp, attribution,
and every accounting field. Unique event IDs reject replay, SQLite triggers reject updates and
deletes, and all cost reads verify every active signature before returning or aggregating data.
Production requires a dedicated `GLC_LEDGER_SIGNING_KEY` Secret of at least 32 bytes.

Existing unsigned rows cannot be authenticated retroactively. Startup therefore moves the old table
transactionally to `calls_legacy_unsigned` for forensics and starts a clean signed table; quarantined
rows never contribute to trusted totals. An invalid schema, missing trigger, invalid signature,
duplicate event, or missing production key fails closed and makes ledger health unavailable.

The existing container boundary is the other half of the fix: adapter images exclude `glc.db`, the
ledger package, the gateway Volume, and both gateway signing keys. For scoped requests the gateway
binds cost attribution to the authenticated slot, so a Telegram caller submitting `agent="victim"`
is recorded as `telegram`. Trusted local and install-token clients retain their V9 agent labels. The
Modal image filters now normalize the relative paths supplied by the SDK as well as absolute paths
used by local tests, so the documented source boundary is enforced in the deployed images.

**Post-fix evidence.** The exact reproduction now raises `AttributeError` because `glc.db.log_call`
does not exist and the active ledger remains empty. Focused regressions cover the 10-million-token
hard cap, strict types, signed writes, unchanged V9 read shapes, unsigned insert rejection, replay,
append-only mutation blocking, signature tampering, legacy quarantine, production key validation,
slot-bound attribution, policy-worker secret stripping, and gateway-only image/Secret/Volume access.
The final live Modal probe reported `ledger_package_absent=true`,
`ledger_signing_key_absent=true`, `unsigned_ledger_api_absent=true`, every provider key absent,
install-token environment and file access absent, replay HTTP 401, and cross-tool use HTTP 403. The
forged request reached the mock-provider boundary with HTTP 502; authenticated accounting returned
`{"victim":[]}` and recorded all six probe failures under `telegram` with zero tokens and zero cost.
Authenticated `/healthz` returned HTTP 200, and `/v1/calls` preserved its V9 shape without exposing
event IDs or signatures.

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
