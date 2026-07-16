# Security findings

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
