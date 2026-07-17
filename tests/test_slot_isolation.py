"""Static and process-level proof that slot deployments do not receive provider keys."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from glc.isolation.manifest import (
    GATEWAY_ONLY_SECRET_KEYS,
    PROVIDER_SECRET_KEYS,
    _parse,
    all_slots,
    channel_slots,
    voice_slots,
)


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


def test_slots_never_include_gateway_only_secrets():
    for slot in all_slots():
        assert GATEWAY_ONLY_SECRET_KEYS.isdisjoint(slot.secret_keys), slot.name


def test_manifest_rejects_gateway_only_secret_keys():
    with pytest.raises(RuntimeError, match="gateway-only secrets"):
        _parse(
            {
                "name": "hostile",
                "kind": "channel",
                "package": "glc.channels.catalogue.hostile",
                "runtime": "webhook",
                "secret_name": "hostile-secret",
                "secret_keys": ["GLC_INSTALL_TOKEN"],
            }
        )


def test_gateway_and_telegram_image_filters_enforce_code_boundary():
    import modal_app
    import modal_telegram

    root = Path(modal_app.__file__).parent / "glc"
    assert modal_app._gateway_ignore(root / "channels/catalogue/telegram/adapter.py")
    assert modal_app._gateway_ignore(root / "voice/stt/providers/groq_whisper/adapter.py")
    assert not modal_app._gateway_ignore(root / "providers.py")
    assert not modal_app._gateway_ignore(root / "voice/tts/providers/system_fallback/adapter.py")
    assert modal_app._gateway_ignore(Path("channels/catalogue/telegram/adapter.py"))
    assert not modal_app._gateway_ignore(Path("providers.py"))

    assert not modal_telegram._ignore(root / "channels/catalogue/telegram/adapter.py")
    assert modal_telegram._ignore(root / "channels/catalogue/discord/adapter.py")
    assert modal_telegram._ignore(root / "providers.py")
    assert modal_telegram._ignore(root / "routes/chat.py")
    assert modal_telegram._ignore(root / "security/pairing.py")
    assert modal_telegram._ignore(root / "security/trust_level.py")
    assert modal_telegram._ignore(root / "config.py")
    assert modal_telegram._ignore(root / "db.py")
    assert modal_telegram._ignore(root / "ledger/writer.py")
    assert not modal_telegram._ignore(Path("channels/catalogue/telegram/adapter.py"))
    assert modal_telegram._ignore(Path("db.py"))
    assert modal_telegram._ignore(Path("ledger/writer.py"))


def test_audit_volume_is_mounted_only_on_gateway_function():
    import modal_app
    import modal_telegram

    assert set(modal_app.fastapi_app.spec.volumes) == {"/data"}
    assert repr(modal_app.fastapi_app.spec.volumes["/data"]) == repr(modal_app.data_volume)
    assert modal_telegram.telegram_adapter.spec.volumes == {}
    assert modal_telegram.security_probe.spec.volumes == {}


def test_install_token_secret_is_bound_only_to_gateway_function():
    import modal_app
    import modal_telegram

    install_secret = repr(modal_app.install_token_secret)
    gateway_secrets = {repr(secret) for secret in modal_app.fastapi_app.spec.secrets}
    assert install_secret in gateway_secrets
    assert install_secret not in {repr(secret) for secret in modal_telegram.telegram_adapter.spec.secrets}
    assert install_secret not in {repr(secret) for secret in modal_telegram.security_probe.spec.secrets}


def test_ledger_signing_secret_is_bound_only_to_gateway_function():
    import modal_app
    import modal_telegram

    ledger_secret = repr(modal_app.ledger_signing_secret)
    gateway_secrets = {repr(secret) for secret in modal_app.fastapi_app.spec.secrets}
    assert ledger_secret in gateway_secrets
    assert ledger_secret not in {repr(secret) for secret in modal_telegram.telegram_adapter.spec.secrets}
    assert ledger_secret not in {repr(secret) for secret in modal_telegram.security_probe.spec.secrets}


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
        "candidate=os.path.join(os.getenv('GLC_CONFIG_DIR', '.'), 'install_token'); "
        "print(json.dumps({"
        "'provider_keys_present': {key: key in os.environ for key in keys}, "
        "'install_token_env_present': 'GLC_INSTALL_TOKEN' in os.environ, "
        "'ledger_signing_key_present': 'GLC_LEDGER_SIGNING_KEY' in os.environ, "
        "'install_token_file_readable': os.path.isfile(candidate) and os.access(candidate, os.R_OK)"
        "}, sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=adapter_env,
        check=True,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    evidence = json.loads(result.stdout)
    assert all(value is False for value in evidence["provider_keys_present"].values())
    assert evidence["install_token_env_present"] is False
    assert evidence["ledger_signing_key_present"] is False
    assert evidence["install_token_file_readable"] is False


def test_channel_adapters_do_not_import_gateway_pairing_or_trust_code():
    catalogue = Path(__file__).parents[1] / "glc" / "channels" / "catalogue"
    adapters = sorted(catalogue.glob("*/adapter.py"))
    assert len(adapters) == 15
    forbidden = (
        "glc.security.pairing",
        "glc.security.trust_level",
        "glc.security.allowlists",
        "get_pairing_store",
        "force_pair_owner",
    )
    for adapter in adapters:
        source = adapter.read_text()
        assert not any(name in source for name in forbidden), adapter
