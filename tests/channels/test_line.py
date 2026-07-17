"""LINE adapter tests.

Wire-format basis: LINE Messaging API.
https://developers.line.biz/en/reference/messaging-api/

Six structural tests + one behavioural test (reply-token-vs-push
selection).
"""

from __future__ import annotations

from datetime import datetime

import pytest

from glc.channels.catalogue.line.adapter import Adapter
from glc.channels.envelope import ChannelIngress, ChannelReply
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.line_mock import OWNER_ID, STRANGER_ID, LineMock
from tests.pairing_helpers import pair_owner as seed_owner


@pytest.fixture
def mock():
    return LineMock()


@pytest.fixture
def pair_owner():
    store = get_pairing_store()
    seed_owner(store, "line", OWNER_ID, user_handle="owner")
    yield
    store.revoke("line", OWNER_ID)


@pytest.mark.asyncio
async def test_on_message_owner_returns_valid_envelope(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("hello from owner")
    msg = await adapter.on_message(ev)
    assert isinstance(msg, ChannelIngress)
    assert msg.channel == "line"
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level is None
    assert msg.text == "hello from owner"
    assert isinstance(msg.arrived_at, datetime)


@pytest.mark.asyncio
async def test_on_message_stranger_is_untrusted(mock):
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_stranger_message("hi")
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert msg.channel_user_id == STRANGER_ID
    assert msg.trust_level is None


@pytest.mark.asyncio
async def test_send_emits_valid_wire_payload(mock, pair_owner):
    """The reply endpoint requires `replyToken` and a `messages` array
    of objects (NOT a bare `text`). The push endpoint requires `to`
    and `messages`."""
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("seed")
    await adapter.on_message(ev)
    reply = ChannelReply(channel="line", channel_user_id=OWNER_ID, text="hi back")
    await adapter.send(reply)
    assert len(mock.send_log) == 1
    body = mock.send_log[0]
    assert "messages" in body, "LINE replies require a `messages` array"
    assert isinstance(body["messages"], list)
    first = body["messages"][0]
    assert first.get("type") == "text"
    assert first.get("text") == "hi back"


@pytest.mark.asyncio
async def test_disconnect_is_handled(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    mock.force_disconnect()
    try:
        await adapter.on_message(mock.queue_owner_message("after disconnect"))
    except Exception as e:
        pytest.fail(f"adapter did not handle disconnect cleanly: {e!r}")


@pytest.mark.asyncio
async def test_rate_limit_propagates_429(mock, pair_owner):
    mock.rate_limited = True
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(channel="line", channel_user_id=OWNER_ID, text="x")
    result = await adapter.send(reply)
    assert isinstance(result, dict)
    assert result.get("status") == 429


@pytest.mark.asyncio
async def test_allowlist_silently_drops_stranger_in_public(mock):
    adapter = Adapter(config={"mock": mock, "is_public_channel": True})
    ev = mock.queue_stranger_message("hi from public")
    msg = await adapter.on_message(ev)
    assert msg is None or msg.trust_level is None


@pytest.mark.asyncio
async def test_was_mentioned_is_derived_from_line_event(mock):
    adapter = Adapter(config={"mock": mock, "was_mentioned": True})
    ordinary = mock.queue_stranger_message("ordinary message")
    ordinary_msg = await adapter.on_message(ordinary)
    assert ordinary_msg is not None
    assert ordinary_msg.metadata["was_mentioned"] is False

    mentioned = mock.queue_stranger_message("hello bot")
    mentioned["events"][0]["message"]["mention"] = {
        "mentionees": [{"index": 0, "length": 3, "type": "user", "isSelf": True}]
    }
    mentioned_msg = await adapter.on_message(mentioned)
    assert mentioned_msg is not None
    assert mentioned_msg.metadata["was_mentioned"] is True


def test_live_bridge_rejects_plaintext_remote_gateway_urls():
    from glc.channels.catalogue.line.dev.live_bridge import BridgeConfig

    with pytest.raises(ValueError, match="must use wss"):
        BridgeConfig(None, None, "ws://gateway.example/v1/channels/line", "mock-identity")

    BridgeConfig(None, None, "ws://127.0.0.1:8111/v1/channels/line", "mock-identity")
    BridgeConfig(None, None, "wss://gateway.example/v1/channels/line", "mock-identity")


@pytest.mark.asyncio
async def test_live_bridge_drop_uses_gateway_called_key(capsys):
    from glc.channels.catalogue.line.dev.live_bridge import BridgeConfig, handle_text_event

    class DroppingAdapter:
        async def on_message(self, raw):  # noqa: ARG002
            return None

    async def unexpected_relay(message):  # pragma: no cover
        raise AssertionError(message)

    result = await handle_text_event(
        adapter=DroppingAdapter(),  # type: ignore[arg-type]
        event={},
        destination=None,
        config=BridgeConfig(None, None, "ws://127.0.0.1:8111/v1/channels/line", "mock-identity"),
        relay_gateway=unexpected_relay,
    )

    assert result == {"gateway_called": False, "dropped": True}
    assert "inbound dropped before relay" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_live_bridge_does_not_log_message_or_user(mock, capsys):
    from glc.channels.catalogue.line.dev.live_bridge import BridgeConfig, handle_text_event

    async def relay(message):
        return ChannelReply(channel="line", channel_user_id=message.channel_user_id, text="ok")

    incoming = mock.queue_owner_message("private message contents")
    result = await handle_text_event(
        adapter=Adapter(config={"transport": mock}),
        event=incoming["events"][0],
        destination=incoming["destination"],
        config=BridgeConfig(None, None, "ws://127.0.0.1:8111/v1/channels/line", "mock-identity"),
        relay_gateway=relay,
    )

    output = capsys.readouterr().out
    assert result["gateway_called"] is True
    assert "private message contents" not in output
    assert OWNER_ID not in output
    assert "event accepted for gateway relay" in output


@pytest.mark.asyncio
async def test_channel_specific_behaviour_reply_token_then_push(mock, pair_owner):
    """LINE reply tokens are one-shot and quota-free; push messages
    cost against the monthly quota. The adapter must:
      - parse the inbound webhook and stash `replyToken` in a TTL
        store keyed by user id (the mock's `consume_reply_token` is
        the read side)
      - emit a reply payload (`{replyToken, messages}`) for the first
        outbound after an inbound
      - fall back to push (`{to, messages}`) for subsequent outbounds
        when no in-flight token is available

    Adapters that always use push will exhaust the monthly quota in
    production and silently drop replies."""
    adapter = Adapter(config={"mock": mock})
    # Inbound primes a reply token.
    ev = mock.queue_owner_message("trigger")
    await adapter.on_message(ev)
    # First reply: must use replyToken.
    await adapter.send(ChannelReply(channel="line", channel_user_id=OWNER_ID, text="first"))
    body1 = mock.send_log[-1]
    assert "replyToken" in body1, "first outbound must consume the reply token"

    # Second reply (no fresh inbound): must use push (`to`).
    await adapter.send(ChannelReply(channel="line", channel_user_id=OWNER_ID, text="second"))
    body2 = mock.send_log[-1]
    assert "to" in body2 and body2.get("to") == OWNER_ID, (
        "second outbound must fall back to push when no replyToken is in flight"
    )
    assert "replyToken" not in body2, "push payload must not include a replyToken"
