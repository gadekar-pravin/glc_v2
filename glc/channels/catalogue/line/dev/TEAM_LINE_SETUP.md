# Secure LINE Slot Setup

This guide configures a LINE provider callback in a separate adapter process.
The slot verifies provider signatures and parses events; only the gateway owns
pairing data, classifies trust, applies allowlists, and runs downstream work.

## 1. Create LINE credentials

Create a LINE Official Account, enable its Messaging API channel, and put these
values in an untracked repo-root `.env`:

```bash
LINE_CHANNEL_ACCESS_TOKEN=<long-lived-token>
LINE_CHANNEL_SECRET=<channel-secret>
LINE_OWNER_USER_ID=<set-after-first-webhook>
GLC_GATEWAY_WS_URL=ws://127.0.0.1:8111/v1/channels/line
GLC_SLOT_IDENTITY_LINE=<random-slot-identity>
```

Configure the same `GLC_SLOT_IDENTITY_LINE` in the gateway environment. Never
commit or print these values, and never give the slot `GLC_PAIRING_DB`, an
install token, or LLM provider keys.

## 2. Start the gateway and isolated slot

Terminal 1:

```bash
uv run glc serve
```

Terminal 2:

```bash
set -a
source .env
set +a
uv run uvicorn glc.channels.catalogue.line.dev.live_bridge:app \
  --host 127.0.0.1 --port 8123
```

Terminal 3 exposes only the slot callback, for example:

```bash
npx --yes localtunnel --port 8123
```

Set the LINE webhook URL to `https://<tunnel-host>/callback`, click Verify, and
enable Use webhook. The gateway's `/v1/channels/line/webhook` route is
intentionally unavailable.

The slot health endpoint should report both `line_configured` and
`gateway_configured` as true:

```bash
curl -s http://127.0.0.1:8123/health
```

## 3. Capture and pair the owner

Send a message to the bot and copy the `U...` value logged as `user_id`. Before
pairing, the gateway will drop the unknown sender; the adapter will not decide
that sender's trust.

Use the gateway's install token from an operator shell, never from the slot:

```bash
export GLC_GATEWAY_URL=http://127.0.0.1:8111
export GLC_INSTALL_TOKEN="$(uv run glc token)"
export LINE_OWNER_USER_ID=Uxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

curl -sS -X POST "$GLC_GATEWAY_URL/v1/control/pair" \
  -H "Authorization: Bearer $GLC_INSTALL_TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"channel\":\"line\",\"channel_user_id\":\"$LINE_OWNER_USER_ID\",\"user_handle\":\"owner\",\"trust_level\":\"owner_paired\"}"
```

Copy the returned six-digit code, then confirm it:

```bash
curl -sS -X POST "$GLC_GATEWAY_URL/v1/control/pair/confirm" \
  -H "Authorization: Bearer $GLC_INSTALL_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"code":"<six-digit-code>"}'

curl -sS "$GLC_GATEWAY_URL/v1/control/presence" \
  -H "Authorization: Bearer $GLC_INSTALL_TOKEN"
```

No slot restart or WebSocket reconnect is needed after pairing; the gateway
reads current pairing state on every message.

## 4. Verify

Send another LINE message. The slot log should show ingress and an outbound
LINE request. Trust does not appear in slot logs because it is authoritative
only inside the gateway.

For deterministic offline verification:

```bash
uv run python -m glc.channels.catalogue.line.dev.harness
```

## Troubleshooting

- `gateway_configured=false`: set `GLC_GATEWAY_WS_URL` and
  `GLC_SLOT_IDENTITY_LINE` in the slot.
- WebSocket policy violation: the identity does not match the gateway's LINE
  identity.
- Unknown sender is dropped: pair the exact provider `source.userId` through
  the authenticated control-plane flow above.
- LINE receives nothing: verify the tunnel, `/callback`, Use webhook, channel
  secret, and access token.
- Do not fix pairing by mounting the SQLite file into the slot. That restores
  the process-boundary vulnerability this setup is designed to remove.
