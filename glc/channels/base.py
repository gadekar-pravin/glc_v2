"""ChannelAdapter ABC. Every adapter under glc/channels/catalogue/<name>/
subclasses this. Two methods: on_message (inbound) and send (outbound).
Both speak the typed envelopes from envelope.py."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from glc.channels.envelope import ChannelIngress, ChannelReply


class ChannelAdapter(ABC):
    name: str = ""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    @abstractmethod
    async def on_message(self, raw: Any) -> ChannelIngress | None:
        """Translate a native wire-format event into a ChannelIngress.

        The wire format is channel-specific (Telegram Update, Discord
        gateway dispatch, Slack event payload, ...).  Adapters report provider
        facts only; the gateway assigns the authenticated channel and trust
        level. Events that an adapter ignores are represented by ``None``.
        """
        raise NotImplementedError("Group assignment: implement on_message and send in this adapter.")

    @abstractmethod
    async def send(self, reply: ChannelReply) -> Any:
        """Translate a ChannelReply into a native wire-format payload and
        dispatch it. Returns whatever the native API returns (often the
        sent-message id, used for thread bookkeeping)."""
        raise NotImplementedError("Group assignment: implement on_message and send in this adapter.")
