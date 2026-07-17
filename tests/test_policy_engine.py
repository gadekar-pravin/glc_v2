"""Policy engine — rule ordering, deny-wins, condition matching,
defaults, hot reload, malformed-yaml safe default."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from textwrap import dedent

import pytest

from glc.policy.client import PolicyWorkerError, ProcessPolicyClient
from glc.policy.engine import PolicyEngine
from glc.policy.schemas import PolicyConfig, PolicyRule, PolicyVerdict


def _engine(rules):
    return PolicyEngine(PolicyConfig(rules=rules))


def test_first_match_wins():
    eng = _engine(
        [
            PolicyRule(tool="email.send", action="allow", reason="first"),
            PolicyRule(tool="email.send", action="deny", reason="second"),
        ]
    )
    v = eng.evaluate({"name": "email.send", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    # Both match; deny-on-tie wins.
    assert v.action == "deny"


def test_first_match_when_no_deny():
    eng = _engine(
        [
            PolicyRule(tool="email.send", action="require_approval", reason="A"),
            PolicyRule(tool="email.send", action="allow", reason="B"),
        ]
    )
    v = eng.evaluate({"name": "email.send", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "require_approval"
    assert v.reason == "A"


def test_default_allow_for_owner_paired():
    eng = _engine([])
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "allow"


def test_default_deny_for_untrusted():
    eng = _engine([])
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})
    assert v.action == "deny"


def test_glob_condition():
    eng = _engine(
        [
            PolicyRule(
                tool="file.delete",
                condition={"path_glob": "~/Documents/**"},
                action="deny",
                reason="docs are protected",
            ),
        ]
    )
    v = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": "~/Documents/secrets/keys.txt"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


def test_glob_does_not_match_other_paths():
    eng = _engine(
        [
            PolicyRule(tool="file.delete", condition={"path_glob": "~/Documents/**"}, action="deny"),
        ]
    )
    v = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": "/tmp/junk.txt"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "allow"


def test_command_matches_list():
    eng = _engine(
        [
            PolicyRule(tool="shell.exec", condition={"command_matches": ["sudo", "rm -rf"]}, action="deny"),
        ]
    )
    v = eng.evaluate(
        {"name": "shell.exec", "arguments": {"command": "sudo apt install"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


def test_untrusted_wildcard_deny():
    eng = _engine(
        [
            PolicyRule(tool="*", trust_level="untrusted", action="deny", reason="no untrusted"),
        ]
    )
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})
    assert v.action == "deny"


def test_recipient_type_external_requires_approval():
    eng = _engine(
        [
            PolicyRule(
                tool="email.send", condition={"recipient_type": "external"}, action="require_approval"
            ),
        ]
    )
    v = eng.evaluate(
        {"name": "email.send", "arguments": {"recipient_type": "external"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "require_approval"


def test_malformed_yaml_falls_back_to_deny(tmp_path):
    bad = tmp_path / "policy.yaml"
    bad.write_text("rules: not-a-list\n  this is broken: [")
    eng = PolicyEngine.from_yaml(bad)
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "deny"


def test_default_policy_yaml_loads_and_matches_lecture():
    """The five rules from §10 of the lecture must load and behave as
    documented."""
    from glc.config import PACKAGED_POLICY

    eng = PolicyEngine.from_yaml(PACKAGED_POLICY)
    deny = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": "~/Documents/x.txt"}},
        {"channel": "telegram", "trust_level": "owner_paired"},
    )
    assert deny.action == "deny"
    approve = eng.evaluate(
        {"name": "email.send", "arguments": {"recipient_type": "external"}},
        {"channel": "slack", "trust_level": "owner_paired"},
    )
    assert approve.action == "require_approval"
    deny_shell = eng.evaluate(
        {"name": "shell.exec", "arguments": {"command": "sudo apt install x"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert deny_shell.action == "deny"
    deny_untrusted = eng.evaluate(
        {"name": "anything", "arguments": {}},
        {"channel": "x", "trust_level": "untrusted"},
    )
    assert deny_untrusted.action == "deny"


def test_reload_picks_up_new_rules(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        dedent("""\
        rules:
          - tool: tool.x
            action: allow
            reason: original
    """)
    )
    eng = PolicyEngine.from_yaml(p)
    v = eng.evaluate({"name": "tool.x", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "allow"

    p.write_text(
        dedent("""\
        rules:
          - tool: tool.x
            action: deny
            reason: rewritten
    """)
    )
    eng.reload(p)
    v2 = eng.evaluate({"name": "tool.x", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v2.action == "deny"
    assert v2.reason == "rewritten"


def test_process_worker_reloads_policy(tmp_path):
    from glc import config

    p = config.CONFIG_DIR / "policy.yaml"
    p.write_text("rules:\n  - {tool: ping, action: allow, reason: v1}\n")
    client = ProcessPolicyClient()
    client.start()
    try:
        v = client.evaluate(
            {"name": "ping", "arguments": {}},
            {"channel": "x", "trust_level": "owner_paired"},
        )
        assert v.action == "allow"
        p.write_text("rules:\n  - {tool: ping, action: deny, reason: v2}\n")
        assert client.reload()
        v2 = client.evaluate(
            {"name": "ping", "arguments": {}},
            {"channel": "x", "trust_level": "owner_paired"},
        )
        assert v2.action == "deny"
        assert v2.reason == "v2"
    finally:
        client.close()


def test_gateway_monkeypatch_cannot_change_worker_decisions(monkeypatch):
    """Leak 5 regression: the supplied rebind only changes this interpreter."""
    import glc.policy.engine as engine_module

    allow = lambda *a, **k: PolicyVerdict(action="allow", reason="pwn")  # noqa: E731
    monkeypatch.setattr(engine_module, "evaluate", allow, raising=False)
    monkeypatch.setattr(PolicyEngine, "evaluate", allow)

    client = ProcessPolicyClient()
    client.start()
    try:
        assert client.worker_pid is not None
        assert client.worker_pid != os.getpid()
        verdict = client.evaluate(
            {"name": "anything", "arguments": {}},
            {"channel": "x", "trust_level": "untrusted"},
        )
        assert verdict.action == "deny"

        monkeypatch.setattr(
            engine_module,
            "evaluate",
            lambda *a, **k: PolicyVerdict(action="allow", reason="pwn-again"),
        )
        verdict_after = client.evaluate(
            {"name": "anything", "arguments": {}},
            {"channel": "x", "trust_level": "untrusted"},
        )
        assert verdict_after.action == "deny"
    finally:
        client.close()


def test_process_worker_malformed_reload_falls_back_to_deny():
    from glc import config

    p = config.CONFIG_DIR / "policy.yaml"
    p.write_text("rules:\n  - {tool: ping, action: allow, reason: before}\n")
    client = ProcessPolicyClient()
    client.start()
    try:
        p.write_text("rules: not-a-list\n  broken: [")
        assert client.reload()
        verdict = client.evaluate(
            {"name": "ping", "arguments": {}},
            {"channel": "x", "trust_level": "owner_paired"},
        )
        assert verdict.action == "deny"
        assert "deny-everything" in verdict.reason
    finally:
        client.close()


def test_process_worker_serializes_concurrent_evaluations():
    client = ProcessPolicyClient()
    client.start()
    try:

        def evaluate(_index):
            return client.evaluate(
                {"name": "anything", "arguments": {}},
                {"channel": "x", "trust_level": "untrusted"},
            ).action

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert list(pool.map(evaluate, range(32))) == ["deny"] * 32
    finally:
        client.close()


def test_process_worker_receives_no_gateway_secrets(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/private/tmp/attacker-controlled")
    monkeypatch.setenv("GEMINI_API_KEY", "mock-not-real")
    monkeypatch.setenv("GLC_INSTALL_TOKEN", "mock-not-real")
    monkeypatch.setenv("GLC_CREDS_SIGNING_KEY", "mock-not-real")
    monkeypatch.setenv("GLC_LEDGER_SIGNING_KEY", "mock-not-real")
    monkeypatch.setenv("GLC_SLOT_IDENTITY_TELEGRAM", "mock-not-real")
    client = ProcessPolicyClient()
    client.start()  # startup rejects a worker that reports any sensitive environment variable
    try:
        assert client.ping()
    finally:
        client.close()


def test_process_worker_shutdown_is_graceful():
    client = ProcessPolicyClient()
    client.start()
    process = client._process
    assert process is not None
    client.close()
    assert process.poll() == 0


def test_process_worker_crash_fails_closed():
    client = ProcessPolicyClient()
    client.start()
    process = client._process
    assert process is not None
    process.terminate()
    process.wait(timeout=2)
    verdict = client.evaluate(
        {"name": "anything", "arguments": {}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert verdict.action == "deny"
    assert verdict.reason == "policy worker unavailable"
    assert not client.ping()
    client.close()


def test_invalid_worker_protocol_fails_closed(monkeypatch):
    client = ProcessPolicyClient()
    client.start()

    def malformed(*args, **kwargs):
        raise PolicyWorkerError("policy worker returned malformed JSON")

    monkeypatch.setattr(client, "_exchange_locked", malformed)
    verdict = client.evaluate(
        {"name": "anything", "arguments": {}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert verdict.action == "deny"
    assert verdict.reason == "policy worker unavailable"
    assert not client.ping()
    client.close()


def test_policy_worker_timeout_fails_closed(monkeypatch):
    import glc.policy.client as client_module

    client = ProcessPolicyClient()
    client.start()

    class NoEventsSelector:
        def register(self, *args, **kwargs):
            return None

        def select(self, timeout=None):
            return []

        def close(self):
            return None

    monkeypatch.setattr(client_module.selectors, "DefaultSelector", NoEventsSelector)
    verdict = client.evaluate(
        {"name": "anything", "arguments": {}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert verdict.action == "deny"
    assert verdict.reason == "policy worker unavailable"
    assert not client.ping()
    client.close()


def test_policy_worker_partial_line_still_obeys_timeout():
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-c",
            "import sys,time; sys.stdout.write('{'); sys.stdout.flush(); time.sleep(1)",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    client = ProcessPolicyClient(operation_timeout=0.05)
    client._process = process
    try:
        with pytest.raises(PolicyWorkerError, match="timed out"):
            client._exchange_locked("ping", timeout=0.05)
    finally:
        client._terminate_locked()


@pytest.mark.asyncio
async def test_sighup_handler_schedules_reload_outside_signal_context(monkeypatch):
    import glc.main as main_module

    installed = {}
    reload_threads = []

    class StubPolicyClient:
        def reload(self):
            reload_threads.append(threading.get_ident())
            return True

    monkeypatch.setattr(
        main_module.signal,
        "signal",
        lambda signal_number, handler: installed.update(handler=handler),
    )

    main_module._install_sighup_reload(StubPolicyClient())
    installed["handler"](None, None)
    assert reload_threads == []

    for _ in range(50):
        if reload_threads:
            break
        await asyncio.sleep(0.01)

    assert reload_threads
    assert reload_threads[0] != threading.get_ident()


def test_gateway_health_fails_when_policy_worker_dies(app_client):
    process = app_client.app.state.policy_client._process
    assert process is not None
    process.terminate()
    process.wait(timeout=2)
    response = app_client.get("/healthz")
    assert response.status_code == 503
    assert response.json() == {"ok": False, "port": 8111, "policy": "unavailable"}


def test_production_modules_do_not_import_the_in_process_engine():
    glc_root = Path(__file__).parents[1] / "glc"
    violations = []
    for path in glc_root.rglob("*.py"):
        relative = path.relative_to(glc_root)
        if relative.parts[0] == "policy" or "tests" in relative.parts:
            continue
        source = path.read_text()
        if "glc.policy.engine" in source or "PolicyEngine" in source:
            violations.append(str(relative))
    assert violations == []
