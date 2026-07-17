# WhatsApp Isolated-Slot E2E Testing

The WhatsApp webhook receiver must run separately from the gateway. It verifies
Meta or Twilio signatures, emits a `ChannelIngress`, and forwards that ingress
to `/v1/channels/whatsapp` using `GLC_SLOT_IDENTITY_WHATSAPP`. Pairing state and
authoritative trust never enter the adapter process.

## Local tests

```bash
uv run pytest tests/channels/test_whatsapp.py \
  glc/channels/catalogue/whatsapp/tests/test_twilio_path.py
```

These tests cover provider parsing, signature verification, outbound payloads,
disconnects, and rate-limit propagation. Gateway trust enrichment is tested in
`tests/test_credentials.py`.

## Live setup

Configure the provider credentials required by `adapter.py`, plus:

```bash
GLC_GATEWAY_WS_URL=ws://127.0.0.1:8111/v1/channels/whatsapp
GLC_SLOT_IDENTITY_WHATSAPP=<random-slot-identity>
```

The gateway must have the same slot identity. Start the gateway on port 8111,
then run the receiver on a different port and expose only that receiver through
an HTTPS tunnel. Do not run the receiver instead of the gateway and do not mount
`GLC_PAIRING_DB` into it.

## Pair the owner

From an operator shell with the gateway install token:

```bash
curl -sS -X POST http://127.0.0.1:8111/v1/control/pair \
  -H "Authorization: Bearer $GLC_INSTALL_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"channel":"whatsapp","channel_user_id":"<provider-sender-id>","user_handle":"owner","trust_level":"owner_paired"}'

curl -sS -X POST http://127.0.0.1:8111/v1/control/pair/confirm \
  -H "Authorization: Bearer $GLC_INSTALL_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"code":"<six-digit-code>"}'
```

Use the exact normalized sender ID emitted by the provider (`WaId` for Twilio,
or the Meta `from` field). Confirm with authenticated
`GET /v1/control/presence`; do not inspect SQLite from the slot.

## Expected behavior

- An unknown sender is rejected by the gateway even if an ingress envelope
  claims `trust_level="owner_paired"`.
- A paired owner succeeds even if the legacy envelope claims `untrusted`.
- Pairing changes take effect on the next message without a slot reconnect.
- The receiver log reports provider facts and gateway decisions, never locally
  computed trust.
