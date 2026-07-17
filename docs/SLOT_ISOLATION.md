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

uv run modal secret create glc-ledger-signing-key \
  GLC_LEDGER_SIGNING_KEY=<different-at-least-32-random-bytes>

uv run modal secret create telegram-slot-identity \
  GLC_SLOT_IDENTITY_TELEGRAM=<random-identity>

uv run modal secret create telegram-channel-secret \
  TELEGRAM_BOT_TOKEN=mock-not-real

uv run modal secret create telegram-gateway-url \
  GLC_GATEWAY_URL=https://<workspace>--glc-v1-gateway-fastapi-app.modal.run

uv run modal deploy modal_app.py
uv run modal deploy modal_telegram.py
```

The gateway attaches `glc-install-token`, `glc-llm-keys`, `glc-creds-signing-key`,
`glc-ledger-signing-key`, and the identities of deployed slots. The Telegram deployment attaches only `telegram-channel-secret`,
`telegram-slot-identity`, and `telegram-gateway-url`. Add a slot by creating the manifest-named
channel/provider secret and a `<slot>-slot-identity` Secret containing the manifest's
`GLC_SLOT_IDENTITY_<SLOT>` key.

The two signing keys have separate purposes and must not be reused. `GLC_CREDS_SIGNING_KEY` signs
short-lived tool credentials. `GLC_LEDGER_SIGNING_KEY` signs authoritative cost records. Neither key,
the ledger package, `glc.db`, nor the gateway Volume is present in an adapter image. Local development
derives a stable ledger key from its installation token when the dedicated environment variable is
absent; production refuses to start without the dedicated Secret.

The control token has a separate gateway-only Secret. Generate at least 32 random bytes, retain the
operator copy in a password manager, and never place the value in shell history or logs. On macOS,
the following shape stores the operator copy in Keychain before creating the Modal Secret:

```sh
INSTALL_TOKEN="$(uv run python -c 'import secrets; print(secrets.token_urlsafe(32))')"
security add-generic-password -U -a <operator-account> \
  -s glc-v1-gateway-install-token -w "$INSTALL_TOKEN"
uv run modal secret create glc-install-token \
  GLC_INSTALL_TOKEN="$INSTALL_TOKEN" --force
unset INSTALL_TOKEN
```

Only `fastapi_app` attaches `glc-install-token`. Production fails closed if the Secret is absent or
empty and never falls back to the legacy Volume file. After a successful migration and authenticated
health check, remove that stale file with
`uv run modal volume rm glc-data glc/install_token`. Local development continues to use
`uv run glc token` and its user-only file.

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

Expected evidence: all six provider-key presence values are `false`,
`install_token_env_absent=true`, `install_token_file_readable=false`, `pairing_api_absent=true`, and
`forged_owner_rejected=true`. Ledger evidence must report `ledger_signing_key_absent=true`,
`ledger_package_absent=true`, and `unsigned_ledger_api_absent=true`. The first chat request submits a
forged `agent="victim"` but is accounted to the authenticated `telegram` slot before it reaches the
provider boundary (normally 502/503 with mock keys). Replay returns 401, cross-tool use returns 403,
and the intended use after that denial still reaches the provider boundary.
