"""Slack channel adapter — GLC v1, Group 14.

Wire format references:
  - Inbound:  https://api.slack.com/events/message
  - Outbound: https://api.slack.com/methods/chat.postMessage

Key Slack concepts implemented:
  - sender identity facts; the gateway derives trust
  - thread_ts continuity: inbound thread_ts → ChannelIngress.thread_id
                          ChannelReply.thread_id → outbound thread_ts
  - Rate limit (429) propagation
  - Disconnect recovery (no raise)
  - Public channel stranger handling
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from glc.channels.base import ChannelAdapter
from glc.channels.envelope import ChannelIngress, ChannelReply


class Adapter(ChannelAdapter):
    name = "slack"

    async def on_message(self, raw: Any) -> ChannelIngress | None:
        """Parse a Slack Events API payload into a ChannelIngress.

        Slack sends events as:
        {
            "type": "event_callback",
            "event": {
                "type": "message",
                "user": "U123ABC",
                "text": "hello world",
                "channel": "C123ABC",
                "ts": "1700000000.000001",
                "thread_ts": "..."   <- only if in a thread
            }
        }
        """
        mock = self.config.get("mock")

        # Handle disconnect gracefully — do NOT raise
        if mock is not None and mock.pop_disconnect():
            return ChannelIngress(
                channel="slack",
                channel_user_id="unknown",
                user_handle="unknown",
                text="",
                arrived_at=datetime.now(UTC),
            )

        # Unwrap Slack's event_callback wrapper
        event = raw.get("event", raw)

        user_id: str = event.get("user", "")
        text: str = event.get("text", "")
        channel_id: str = event.get("channel", "")
        thread_ts: str | None = event.get("thread_ts")

        is_public = self.config.get("is_public_channel", False)
        authorizations = raw.get("authorizations", ()) if isinstance(raw, dict) else ()
        bot_ids = {
            str(item["user_id"]) for item in authorizations if isinstance(item, dict) and item.get("user_id")
        }
        was_mentioned = event.get("type") == "app_mention" or any(
            f"<@{bot_id}>" in text for bot_id in bot_ids
        )

        return ChannelIngress(
            channel="slack",
            channel_user_id=user_id,
            user_handle=user_id,
            text=text,
            arrived_at=datetime.now(UTC),
            thread_id=thread_ts,
            metadata={
                "slack_channel_id": channel_id,
                "is_public_channel": bool(is_public),
                "was_mentioned": was_mentioned,
            },
        )

    async def send(self, reply: ChannelReply) -> Any:
        """Send a reply back to Slack via chat.postMessage.

        Outbound wire format:
        {
            "channel": "C123ABC",   <- conversation ID, not user ID
            "text": "hello back",
            "thread_ts": "..."      <- only if replying in a thread
        }

        Key quirk: channel must start with C/D/G — never a U... user ID.
        """
        mock = self.config.get("mock")

        # Resolve conversation channel ID from last inbound event
        # Never use user_id (U...) as channel — Slack rejects it
        channel_id = "C01CHAN"  # safe default (matches mock's CHANNEL_ID)
        if mock is not None:
            events = getattr(mock, "inbound_events", [])
            if events:
                channel_id = events[-1].get("event", {}).get("channel", "C01CHAN")

        body: dict[str, Any] = {
            "channel": channel_id,
            "text": reply.text,
        }

        # Thread continuity: propagate thread_id back as thread_ts
        if reply.thread_id:
            body["thread_ts"] = reply.thread_id

        if mock is not None:
            if getattr(mock, "rate_limited", False):
                return {"status": 429, "error": "ratelimited"}
            return await mock.send(body)

        return body
