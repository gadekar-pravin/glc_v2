"""Static and process-level proof that slot deployments do not receive provider keys."""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from glc.isolation.egress import build_slot_egress_allowlist
from glc.isolation.manifest import (
    GATEWAY_ONLY_SECRET_KEYS,
    PROVIDER_SECRET_KEYS,
    _parse,
    all_slots,
    channel_slots,
    get_slot,
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


def test_telegram_manifest_declares_only_its_exact_upstream_domain():
    assert get_slot("telegram").egress_domains == ("api.telegram.org",)


@pytest.mark.parametrize(
    "entry, message",
    [
        ("*", "wildcard"),
        ("*.modal.run", "wildcard"),
        ("https://api.telegram.org", "without scheme"),
        ("api.telegram.org/path", "without scheme"),
        ("api.telegram.org:443", "without scheme"),
        ("127.0.0.1", "IP literal"),
        ("", "must not be empty"),
    ],
)
def test_manifest_rejects_unsafe_egress_domains(entry, message):
    with pytest.raises(RuntimeError, match=message):
        _parse(
            {
                "name": "hostile",
                "kind": "channel",
                "package": "glc.channels.catalogue.hostile",
                "runtime": "webhook",
                "secret_name": "hostile-secret",
                "egress_domains": [entry],
            }
        )


def test_slot_egress_builder_fails_closed_and_adds_exact_gateway_host():
    assert build_slot_egress_allowlist(("api.telegram.org",), "https://workspace--gateway.modal.run") == (
        "api.telegram.org",
        "workspace--gateway.modal.run",
    )
    with pytest.raises(RuntimeError, match="at least one explicit"):
        build_slot_egress_allowlist((), "https://workspace--gateway.modal.run")
    with pytest.raises(RuntimeError, match="must not contain"):
        build_slot_egress_allowlist(("api.telegram.org",), "https://gateway.modal.run/path")


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
    assert modal_telegram.reconcile_telegram_sandbox.spec.volumes == {}
    assert modal_telegram.launch_security_probe.spec.volumes == {}


def test_install_token_secret_is_bound_only_to_gateway_function():
    import modal_app
    import modal_telegram

    install_secret = repr(modal_app.install_token_secret)
    gateway_secrets = {repr(secret) for secret in modal_app.fastapi_app.spec.secrets}
    assert install_secret in gateway_secrets
    assert install_secret not in {
        repr(secret) for secret in modal_telegram.reconcile_telegram_sandbox.spec.secrets
    }
    assert install_secret not in {
        repr(secret) for secret in modal_telegram.launch_security_probe.spec.secrets
    }


def test_ledger_signing_secret_is_bound_only_to_gateway_function():
    import modal_app
    import modal_telegram

    ledger_secret = repr(modal_app.ledger_signing_secret)
    gateway_secrets = {repr(secret) for secret in modal_app.fastapi_app.spec.secrets}
    assert ledger_secret in gateway_secrets
    assert ledger_secret not in {
        repr(secret) for secret in modal_telegram.reconcile_telegram_sandbox.spec.secrets
    }
    assert ledger_secret not in {repr(secret) for secret in modal_telegram.launch_security_probe.spec.secrets}


def test_telegram_supervisor_functions_are_secretless_and_do_not_run_adapter_code():
    import modal_telegram

    assert modal_telegram.reconcile_telegram_sandbox.spec.secrets == []
    assert modal_telegram.launch_security_probe.spec.secrets == []
    source = Path(modal_telegram.__file__).read_text()
    assert "modal.Sandbox.create(" in source
    assert "outbound_domain_allowlist" in source
    assert "copy=True" in source
    assert "from glc.isolation.telegram_runtime import" not in source
    assert "gateway_url_secret" not in source


def test_telegram_sandbox_options_are_exact_and_least_privilege(monkeypatch):
    import modal_telegram

    sandbox_app = object()
    monkeypatch.setattr(modal_telegram.modal.App, "lookup", lambda _name: sandbox_app)
    options = modal_telegram._sandbox_options(
        "https://workspace--glc-v1-gateway-fastapi-app.modal.run", probe=False
    )

    assert options["app"] is sandbox_app
    assert options["env"] == {"GLC_GATEWAY_URL": "https://workspace--glc-v1-gateway-fastapi-app.modal.run"}
    assert [repr(secret) for secret in options["secrets"]] == [
        repr(modal_telegram.channel_secret),
        repr(modal_telegram.identity_secret),
    ]
    assert options["outbound_domain_allowlist"] == [
        "api.telegram.org",
        "workspace--glc-v1-gateway-fastapi-app.modal.run",
    ]
    assert options["cpu"] == 0.25
    assert options["memory"] == 256
    assert options["timeout"] == 86_400
    assert options["volumes"] == {}
    assert options["encrypted_ports"] == []
    assert options["h2_ports"] == []
    assert options["unencrypted_ports"] == []


class _FakeSandbox:
    def __init__(self, sandbox_id: str, returncode=None):
        self.object_id = sandbox_id
        self._returncode = returncode
        self.detached = False

    def poll(self):
        return self._returncode

    def detach(self):
        self.detached = True


def test_supervisor_reuses_running_named_sandbox(monkeypatch):
    import modal_telegram

    running = _FakeSandbox("sb-running")

    class FakeSandboxAPI:
        @staticmethod
        def from_name(_app_name, _sandbox_name):
            return running

    monkeypatch.setattr(modal_telegram.modal, "Sandbox", FakeSandboxAPI)
    monkeypatch.setattr(
        modal_telegram,
        "_deployed_gateway_url",
        lambda: pytest.fail("gateway lookup must not run for a healthy Sandbox"),
    )
    result = modal_telegram._ensure_telegram_sandbox()

    assert result == {"sandbox_id": "sb-running", "status": "running"}
    assert running.detached is True


def test_supervisor_replaces_finished_named_sandbox(monkeypatch):
    import modal_telegram

    finished = _FakeSandbox("sb-finished", returncode=1)
    created = _FakeSandbox("sb-created")

    class FakeSandboxAPI:
        @staticmethod
        def from_name(_app_name, _sandbox_name):
            return finished

    monkeypatch.setattr(modal_telegram.modal, "Sandbox", FakeSandboxAPI)
    monkeypatch.setattr(modal_telegram, "_deployed_gateway_url", lambda: "https://gateway.modal.run")
    monkeypatch.setattr(modal_telegram, "_create_sandbox", lambda _url, probe: created)
    monkeypatch.setattr(
        modal_telegram,
        "_sandbox_options",
        lambda _url, probe: {"outbound_domain_allowlist": ["api.telegram.org", "gateway.modal.run"]},
    )

    result = modal_telegram._ensure_telegram_sandbox()
    assert result["sandbox_id"] == "sb-created"
    assert result["status"] == "created"
    assert finished.detached is True
    assert created.detached is True


def test_supervisor_handles_named_sandbox_creation_race(monkeypatch):
    import modal_telegram

    winner = _FakeSandbox("sb-winner")
    lookups = 0

    class FakeSandboxAPI:
        @staticmethod
        def from_name(_app_name, _sandbox_name):
            nonlocal lookups
            lookups += 1
            if lookups == 1:
                raise modal_telegram.NotFoundError("missing")
            return winner

    def lose_race(_url, probe):
        raise modal_telegram.AlreadyExistsError("created concurrently")

    monkeypatch.setattr(modal_telegram.modal, "Sandbox", FakeSandboxAPI)
    monkeypatch.setattr(modal_telegram, "_deployed_gateway_url", lambda: "https://gateway.modal.run")
    monkeypatch.setattr(modal_telegram, "_create_sandbox", lose_race)
    monkeypatch.setattr(
        modal_telegram,
        "_sandbox_options",
        lambda _url, probe: {"outbound_domain_allowlist": ["api.telegram.org", "gateway.modal.run"]},
    )

    result = modal_telegram._ensure_telegram_sandbox()
    assert result["sandbox_id"] == "sb-winner"
    assert result["status"] == "running"
    assert winner.detached is True


async def test_runtime_network_probe_reports_allowed_and_blocked_hosts():
    from glc.isolation.telegram_runtime import _network_result

    class FakeClient:
        async def get(self, url):
            if url == "https://example.com":
                raise httpx.ConnectError("blocked by policy")
            return httpx.Response(401 if url.endswith("healthz") else 302)

    client = FakeClient()
    assert await _network_result(client, "https://gateway.modal.run/healthz") == {
        "reachable": True,
        "status": 401,
    }
    assert await _network_result(client, "https://api.telegram.org") == {
        "reachable": True,
        "status": 302,
    }
    assert await _network_result(client, "https://example.com") == {
        "reachable": False,
        "status": None,
    }


def test_runtime_gateway_websocket_bypasses_ambient_proxy(monkeypatch):
    import glc.isolation.telegram_runtime as runtime

    sentinel = object()
    captured = {}

    def fake_connect(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return sentinel

    monkeypatch.setenv("GLC_GATEWAY_URL", "https://gateway.modal.run")
    monkeypatch.setattr(runtime.websockets, "connect", fake_connect)

    headers = {"Authorization": "Bearer mock-identity"}
    assert runtime._gateway_websocket(headers) is sentinel
    assert captured == {
        "url": "wss://gateway.modal.run/v1/channels/telegram",
        "additional_headers": headers,
        "proxy": None,
        "open_timeout": 30,
    }


def test_runtime_does_not_hold_a_gateway_websocket_while_polling():
    from glc.isolation.telegram_runtime import run

    source = inspect.getsource(run)
    assert "_gateway_roundtrip" in source
    assert "async with _gateway_websocket" not in source


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
