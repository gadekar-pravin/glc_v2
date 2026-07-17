# LINE Isolated-Slot Harness

`harness.py` is a deterministic driver for the LINE slot runtime. It sends
synthetic signed LINE webhooks through the real FastAPI callback, adapter, and
outbound transport. The offline gateway stub supplies gateway decisions; the
adapter and bridge never read pairing state or assign trust.

## Secure flow

```text
signed LINE webhook
  -> live_bridge /callback (verify X-Line-Signature)
  -> Adapter.on_message()  (provider facts -> ChannelIngress)
  -> authenticated gateway WebSocket /v1/channels/line
  -> gateway pairing classification, allowlist, rate limit, and audit
  -> ChannelReply or drop/rate-limit decision
  -> Adapter.send() to LINE
```

In capture mode, an offline gateway stub models reply, drop, and rate-limit
responses. This seam tests slot behavior without copying the pairing database
or gateway security implementation into the slot.

## Run

```bash
# Offline, deterministic, no credentials or network
uv run python -m glc.channels.catalogue.line.dev.harness

# Send the scripted conversation through a configured live slot
uv run python -m glc.channels.catalogue.line.dev.harness --live

# Run one scenario
uv run python -m glc.channels.catalogue.line.dev.harness --scenario owner
```

Capture mode covers provider signature verification, ingress parsing,
gateway-reply delivery, gateway drops, gateway rate limiting, reply-token use,
disconnect handling, and the absence of adapter-authoritative trust. A run exits
non-zero if any scenario fails.

## Live configuration

The live runtime needs these values in an untracked `.env`:

- `LINE_CHANNEL_ACCESS_TOKEN`
- `LINE_CHANNEL_SECRET`
- `LINE_OWNER_USER_ID`
- `GLC_GATEWAY_WS_URL`, normally `ws://127.0.0.1:8111/v1/channels/line`
- `GLC_SLOT_IDENTITY_LINE`, matching the identity configured on the gateway

Provision the LINE owner only through the install-token-authenticated
`POST /v1/control/pair` and `POST /v1/control/pair/confirm` endpoints. Do not
mount `GLC_PAIRING_DB` or import `glc.security` in the slot.

The synthetic live harness cannot create a genuine LINE reply token, so live
responses use push delivery. Capture mode proves the reply-token behavior.

## Non-goals

- The harness does not classify owners or strangers; that is gateway-only.
- It does not open or seed the pairing SQLite database.
- It does not call an agent directly or bypass the gateway.
- It does not replace the adapter unit tests in `tests/channels/test_line.py`.
