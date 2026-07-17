# Telegram Bot API

This is a **group assignment** in Session 11. Implement the telegram adapter
to make the test suite at `tests/channels/test_telegram.py` pass.

## What you build

Two files under this directory:

- `adapter.py` — subclass `glc.channels.base.ChannelAdapter` and implement
  `on_message(raw) -> ChannelIngress` and `send(reply) -> Any`.
- `schemas.py` — any channel-specific Pydantic types you need.

## Required environment variables

- `TELEGRAM_BOT_TOKEN`

## Free-tier limits

Unlimited messaging via the Bot API. 30 messages/second per bot soft cap.

## Wire-format quirks to expect

Long-polling vs webhook modes (use long-polling for local development). Markdown vs HTML parse modes need escaping. Inline buttons live in `reply_markup`.

## Tests you need to pass

The failing tests live at `tests/channels/test_telegram.py`. They cover:

1. `on_message` builds a valid `ChannelIngress` from provider-owned facts.
2. The adapter leaves trust unset; the authenticated gateway classifies the sender.
3. `send` produces a valid wire-format payload and reaches the mock.
4. The adapter handles forced disconnects without raising.
5. Rate-limit responses propagate to the caller as a 429.
6. Public-channel and mention context is emitted as metadata so the gateway can
   apply its authoritative allowlist.

The mock-API fake at `tests/channels/mocks/telegram_mock.py` is your contract
surface. Do **not** edit the mock or the test file — they are fixed.

## Submission

Open a PR that:

- Adds your `adapter.py` and `schemas.py`.
- Passes `pytest tests/channels/test_telegram.py`.
- Updates `CLAIMS.md` if you have not already claimed this channel.

CI gates merge through branch protection. A TA reviews before merge.
