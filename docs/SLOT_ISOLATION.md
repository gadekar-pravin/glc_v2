# Slot isolation and per-tool credentials

Leak 1 existed because the gateway and every adapter shared one Python process and therefore one
environment. The production deployment now uses a separate Modal container per slot. The gateway is
the only component that receives `glc-llm-keys`; channel slots receive only their own channel secret
and identity.

The validated source of truth is `glc/isolation/slots.yaml`: 15 channel slots and 7 external voice
slots. `system_fallback` remains inside the gateway because it has no external credential. External
voice slots may receive only their own upstream key. Missing voice-slot URLs fail closed with HTTP
503 in production; the gateway does not import the provider locally.

## Gateway and Telegram reference deployment

Use mock provider/channel values for the assignment. Generate the signing and identity values with a
cryptographic random generator; do not reuse an API key as either value.

```sh
uv run modal secret create glc-creds-signing-key \
  GLC_CREDS_SIGNING_KEY=<at-least-32-random-bytes>

uv run modal secret create telegram-slot-identity \
  GLC_SLOT_IDENTITY_TELEGRAM=<random-identity>

uv run modal secret create telegram-channel-secret \
  TELEGRAM_BOT_TOKEN=mock-not-real

uv run modal secret create telegram-gateway-url \
  GLC_GATEWAY_URL=https://<workspace>--glc-v1-gateway-fastapi-app.modal.run

uv run modal deploy modal_app.py
uv run modal deploy modal_telegram.py
```

The gateway attaches `glc-llm-keys`, `glc-creds-signing-key`, and the identities of deployed slots.
The Telegram deployment attaches only `telegram-channel-secret`, `telegram-slot-identity`, and
`telegram-gateway-url`. Add a slot by creating the manifest-named channel/provider secret and a
`<slot>-slot-identity` Secret containing the manifest's `GLC_SLOT_IDENTITY_<SLOT>` key.

## Credential flow

1. The slot calls `POST /v1/creds/issue` with `{ "tool": "llm.chat", "model": null }` and its
   identity bearer token.
2. The gateway derives the slot from the bearer value and checks the tool against the manifest. The
   request cannot declare an adapter name.
3. The gateway returns a five-minute HS256 JWT containing exact tool scope and a random JTI.
4. The tool route accepts either the existing install token or that scoped JWT. A correct scoped use
   atomically marks the JTI used before provider execution; replay fails with HTTP 401.
5. A wrong tool or model fails with HTTP 403 without consuming the intended grant.

Run the safe Modal probe after deployment. It returns presence booleans and HTTP statuses only; it
never returns secret values:

```sh
uv run modal run modal_telegram.py
```

Expected evidence: all six provider-key presence values are `false`, the first chat request reaches
the provider boundary (normally 502/503 with mock keys), replay returns 401, cross-tool use returns
403, and the intended use after that denial still reaches the provider boundary.
