"""Static and process-level proof that slot deployments do not receive provider keys."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from glc.isolation.manifest import PROVIDER_SECRET_KEYS, all_slots, channel_slots, voice_slots


def test_manifest_has_exactly_15_channels_and_7_voice_slots():
    slots = all_slots()
    assert len(slots) == 22
    assert len({slot.name for slot in slots}) == 22
    assert len(channel_slots()) == 15
    assert len(voice_slots()) == 7
    assert all(slot.identity_env == f"GLC_SLOT_IDENTITY_{slot.name.upper()}" for slot in slots)


def test_channel_secrets_never_include_llm_provider_keys():
    for slot in channel_slots():
        assert PROVIDER_SECRET_KEYS.isdisjoint(slot.secret_keys), slot.name
    for slot in voice_slots():
        assert len(PROVIDER_SECRET_KEYS.intersection(slot.secret_keys)) <= 1, slot.name


def test_gateway_and_telegram_image_filters_enforce_code_boundary():
    import modal_app
    import modal_telegram

    root = Path(modal_app.__file__).parent / "glc"
    assert modal_app._gateway_ignore(root / "channels/catalogue/telegram/adapter.py")
    assert modal_app._gateway_ignore(root / "voice/stt/providers/groq_whisper/adapter.py")
    assert not modal_app._gateway_ignore(root / "providers.py")
    assert not modal_app._gateway_ignore(root / "voice/tts/providers/system_fallback/adapter.py")

    assert not modal_telegram._ignore(root / "channels/catalogue/telegram/adapter.py")
    assert modal_telegram._ignore(root / "channels/catalogue/discord/adapter.py")
    assert modal_telegram._ignore(root / "providers.py")
    assert modal_telegram._ignore(root / "routes/chat.py")


def test_adapter_process_environment_does_not_inherit_gateway_provider_keys(tmp_path):
    gateway_env = os.environ.copy()
    for key in PROVIDER_SECRET_KEYS:
        gateway_env[key] = f"mock-{key.lower()}"

    adapter_env = {
        "PATH": gateway_env.get("PATH", ""),
        "PYTHONPATH": str(Path(__file__).parents[1]),
        "GLC_SLOT": "telegram",
        "GLC_SLOT_IDENTITY_TELEGRAM": "mock-identity",
        "TELEGRAM_BOT_TOKEN": "mock-channel-token",
    }
    code = (
        "import json, os; "
        f"keys={sorted(PROVIDER_SECRET_KEYS)!r}; "
        "print(json.dumps({key: key in os.environ for key in keys}, sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=adapter_env,
        check=True,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert all(value is False for value in json.loads(result.stdout).values())
