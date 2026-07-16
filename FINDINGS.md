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
