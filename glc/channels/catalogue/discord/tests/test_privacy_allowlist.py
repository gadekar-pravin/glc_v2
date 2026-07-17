"""Privacy / allowlist hardening tests for the Discord adapter.

These cover the opt-in inbound gate behaviour added on top of the base
adapter contract:

  - ignore_bots            : drop bot-authored (and self) messages
  - enforce_allowlist_in_dm: gate DM strangers, not just public strangers
  - mention resolution runs only for messages that survive the gate
    (no get_user() lookups on a sender we are about to reject)

The defaults (both flags off) must leave the original contract untouched;
each flag's off-path is asserted alongside its on-path.
"""

from __future__ import annotations

from glc.channels.catalogue.discord.adapter import Adapter
from tests.channels.mocks.discord_mock import (
    CHANNEL_ID,
    GUILD_ID,
    OWNER_ID,
    STRANGER_ID,
    DiscordMock,
)


def _frame(
    *,
    author_id: str,
    username: str = "someone",
    content: str = "hi",
    is_bot: bool = False,
    mentions: list[dict] | None = None,
) -> dict:
    """Build a MESSAGE_CREATE dispatch frame with an arbitrary author.

    The mock's queue_* helpers only emit owner/stranger/mention shapes, so
    bot-authored frames are constructed directly here.
    """
    return {
        "op": 0,
        "t": "MESSAGE_CREATE",
        "s": 1,
        "d": {
            "id": "frame-1",
            "channel_id": CHANNEL_ID,
            "guild_id": GUILD_ID,
            "author": {
                "id": author_id,
                "username": username,
                "global_name": username.capitalize(),
                "discriminator": "0001",
                "avatar": None,
                "bot": is_bot,
            },
            "content": content,
            "timestamp": "2026-06-17T12:00:00.000000+00:00",
            "mentions": mentions or [],
            "attachments": [],
            "type": 0,
        },
    }


# ── ignore_bots ───────────────────────────────────────────────────────────


async def test_bot_message_processed_when_flag_off():
    """Default: bot-authored messages flow through unchanged."""
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(_frame(author_id="7", username="otherbot", is_bot=True))
    assert msg is not None
    assert msg.channel_user_id == "7"


async def test_bot_message_dropped_when_flag_on():
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock, "ignore_bots": True})
    msg = await adapter.on_message(_frame(author_id="7", username="otherbot", is_bot=True))
    assert msg is None


async def test_human_message_survives_ignore_bots():
    """ignore_bots must not affect human authors."""
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock, "ignore_bots": True})
    msg = await adapter.on_message(_frame(author_id="8", username="human", is_bot=False))
    assert msg is not None
    assert msg.channel_user_id == "8"


# ── enforce_allowlist_in_dm ───────────────────────────────────────────────


async def test_dm_stranger_passes_when_flag_off():
    """Default DM behaviour: stranger reaches the agent tagged untrusted."""
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(mock.queue_stranger_message("hi"))
    assert msg is not None
    assert msg.trust_level is None


async def test_dm_enforcement_flag_is_forwarded_to_gateway():
    """The adapter reports the operator's DM policy without enforcing it."""
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock, "enforce_allowlist_in_dm": True})
    msg = await adapter.on_message(mock.queue_stranger_message("hi"))
    assert msg is not None
    assert msg.metadata["enforce_allowlist_in_dm"] is True


async def test_adapter_does_not_consult_pairing_for_owner_identity():
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock, "enforce_allowlist_in_dm": True})
    msg = await adapter.on_message(mock.queue_owner_message("hello"))
    assert msg is not None
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level is None


async def test_channel_enabled_state_is_not_read_by_adapter():
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(mock.queue_owner_message("hello"))
    assert msg is not None


# ── data minimization: no mention lookups for dropped messages ────────────


async def test_public_context_and_mentions_are_forwarded_to_gateway():
    mock = DiscordMock()
    calls: list[str] = []
    original = mock.get_user

    def spy(user_id: str):
        calls.append(user_id)
        return original(user_id)

    mock.get_user = spy  # type: ignore[method-assign]

    adapter = Adapter(config={"mock": mock, "is_public_channel": True})
    frame = _frame(
        author_id=STRANGER_ID,
        username="stranger",
        content="hey <@123> look",
        mentions=[{"id": "123", "username": "alice", "bot": False}],
    )
    msg = await adapter.on_message(frame)
    assert msg is not None
    assert msg.metadata["is_public_channel"] is True
    assert msg.metadata["was_mentioned"] is False
    assert calls == ["123"]


async def test_mentions_resolved_for_admitted_message():
    """The companion path: an admitted message still resolves mentions."""
    mock = DiscordMock()
    calls: list[str] = []
    original = mock.get_user

    def spy(user_id: str):
        calls.append(user_id)
        return original(user_id)

    mock.get_user = spy  # type: ignore[method-assign]

    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(
        mock.queue_mention_message(mentioned_user_id="123", mentioned_username="alice")
    )
    assert msg is not None
    assert "123" in calls
    assert "alice" in msg.metadata["mentions"]
