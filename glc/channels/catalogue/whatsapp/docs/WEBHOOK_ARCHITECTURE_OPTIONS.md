# WhatsApp Webhook Architecture

## Supported topology

WhatsApp requires a public HTTP callback, but that callback must terminate in
an isolated WhatsApp slot runtime, not in the gateway process.

```text
Meta or Twilio
  -> isolated WhatsApp callback
     - verifies provider signature
     - parses provider event
     - emits ChannelIngress facts
  -> authenticated gateway WebSocket /v1/channels/whatsapp
     - binds channel to authenticated slot
     - classifies sender using gateway pairing DB
     - refreshes owner allowlist
     - rate limits and audits authoritative ChannelMessage
  -> ChannelReply
  -> isolated slot sends provider response
```

The provider webhook URL therefore points to the slot. Gateway
`/v1/channels/{name}/webhook` routes intentionally return 404 in every mode.

## Rejected topologies

- Instantiating catalogue adapters inside the gateway webhook route.
- Calling an agent directly from `demo_webhook_server.py`.
- Giving a slot `glc.security`, `glc.config`, an install token, or the pairing
  SQLite database.
- Trusting legacy `channel` or `trust_level` fields from the adapter envelope.

These patterns collapse the process boundary and let compromised adapter code
mutate owner pairings or forge authoritative trust.

## Compatibility

The WebSocket URL and JSON wire remain compatible. Legacy `channel` and
`trust_level` values are accepted as untrusted claims: the gateway normalizes
the channel to `whatsapp` and replaces trust from its current pairing database.
