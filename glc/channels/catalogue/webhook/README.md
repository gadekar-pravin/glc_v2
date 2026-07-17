# Generic Webhook (HTTP in/out)

This is a **group assignment** in Session 11. Implement the webhook adapter
to make the test suite at `tests/channels/test_webhook.py` pass.

## What you build

Two files under this directory:

- `adapter.py` — subclass `glc.channels.base.ChannelAdapter` and implement
  `on_message(raw) -> ChannelIngress` and `send(reply) -> Any`.
- `schemas.py` — any channel-specific Pydantic types you need.

## Required environment variables

- `WEBHOOK_INGRESS_TOKEN`
- `WEBHOOK_DEFAULT_TARGET_URL`

## Free-tier limits

Free — the adapter is an HTTP listener; cost depends on the integrating service.

## Wire-format quirks to expect

Payload shape is caller-defined. Adapter must validate against a per-integration secret token (X-GLC-Token header) before constructing an envelope.

## Tests you need to pass

The failing tests live at `tests/channels/test_webhook.py`. They cover:

1. `on_message` builds a valid `ChannelIngress` from provider-owned facts.
2. The adapter leaves trust unset; the authenticated gateway classifies the sender.
3. `send` produces a valid wire-format payload and reaches the mock.
4. The adapter handles forced disconnects without raising.
5. Rate-limit responses propagate to the caller as a 429.
6. Public-channel and mention context is emitted as metadata so the gateway can
   apply its authoritative allowlist.

The mock-API fake at `tests/channels/mocks/webhook_mock.py` is your contract
surface. Do **not** edit the mock or the test file — they are fixed.

## Submission

Open a PR that:

- Adds your `adapter.py` and `schemas.py`.
- Passes `pytest tests/channels/test_webhook.py`.
- Updates `CLAIMS.md` if you have not already claimed this channel.

CI gates merge through branch protection. A TA reviews before merge.
