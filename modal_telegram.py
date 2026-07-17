"""Deploy a secretless supervisor for the allowlisted Telegram Sandbox."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import modal
from modal.exception import AlreadyExistsError, NotFoundError

from glc.isolation.egress import build_slot_egress_allowlist
from glc.isolation.manifest import get_slot
from modal_images import locked_runtime_image

APP_NAME = "glc-adapter-telegram"
GATEWAY_APP_NAME = "glc-v1-gateway"
GATEWAY_FUNCTION_NAME = "fastapi_app"
SANDBOX_NAME = "telegram-adapter"
SANDBOX_LIFETIME_SECONDS = 24 * 60 * 60
PROBE_TIMEOUT_SECONDS = 180

ROOT = Path(__file__).parent
LOCAL_GLC = ROOT / "glc"

app = modal.App(APP_NAME)


def _ignore(path: Path) -> bool:
    try:
        rel = path.relative_to(LOCAL_GLC)
    except ValueError:
        rel = path
        if rel.parts and rel.parts[0] == LOCAL_GLC.name:
            rel = Path(*rel.parts[1:])
    parts = rel.parts
    if len(parts) >= 3 and parts[:2] == ("channels", "catalogue"):
        return parts[2] != "telegram"
    return bool(
        parts
        and parts[0]
        in {
            "audit",
            "config.py",
            "db.py",
            "ledger",
            "policy",
            "providers.py",
            "routes",
            "security",
            "voice",
        }
    )


image = (
    locked_runtime_image(only_group="telegram-runtime")
    .env({"GLC_SLOT": "telegram"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc", ignore=_ignore, copy=True)
)

channel_secret = modal.Secret.from_name("telegram-channel-secret")
identity_secret = modal.Secret.from_name("telegram-slot-identity")


def _deployed_gateway_url() -> str:
    url = modal.Function.from_name(GATEWAY_APP_NAME, GATEWAY_FUNCTION_NAME).get_web_url()
    if not url:
        raise RuntimeError("deployed gateway web URL is unavailable")
    return url.rstrip("/")


def _sandbox_options(gateway_url: str, *, probe: bool) -> dict[str, Any]:
    slot = get_slot("telegram")
    allowlist = build_slot_egress_allowlist(slot.egress_domains, gateway_url)
    return {
        "app": modal.App.lookup(APP_NAME),
        "image": image,
        "env": {"GLC_GATEWAY_URL": gateway_url},
        "secrets": [channel_secret, identity_secret],
        "cpu": slot.cpu,
        "memory": slot.memory_mb,
        "timeout": PROBE_TIMEOUT_SECONDS if probe else SANDBOX_LIFETIME_SECONDS,
        "outbound_domain_allowlist": list(allowlist),
        "volumes": {},
        "encrypted_ports": [],
        "h2_ports": [],
        "unencrypted_ports": [],
        "tags": {"slot": "telegram", "purpose": "security-probe" if probe else "adapter"},
    }


def _create_sandbox(gateway_url: str, *, probe: bool):
    command = ["python", "-m", "glc.isolation.telegram_runtime"]
    if probe:
        command.append("--security-probe")
    options = _sandbox_options(gateway_url, probe=probe)
    if not probe:
        options["name"] = SANDBOX_NAME
    return modal.Sandbox.create(*command, **options)


def _ensure_telegram_sandbox() -> dict[str, Any]:
    try:
        sandbox = modal.Sandbox.from_name(APP_NAME, SANDBOX_NAME)
    except NotFoundError:
        sandbox = None
    if sandbox is not None:
        try:
            if sandbox.poll() is None:
                return {"sandbox_id": sandbox.object_id, "status": "running"}
        finally:
            sandbox.detach()

    gateway_url = _deployed_gateway_url()
    try:
        sandbox = _create_sandbox(gateway_url, probe=False)
        status = "created"
    except AlreadyExistsError:
        sandbox = modal.Sandbox.from_name(APP_NAME, SANDBOX_NAME)
        status = "running"
    try:
        return {
            "sandbox_id": sandbox.object_id,
            "status": status,
            "outbound_domain_allowlist": _sandbox_options(gateway_url, probe=False)[
                "outbound_domain_allowlist"
            ],
        }
    finally:
        sandbox.detach()


def _run_security_probe() -> dict[str, Any]:
    gateway_url = _deployed_gateway_url()
    sandbox = _create_sandbox(gateway_url, probe=True)
    sandbox_id = sandbox.object_id
    try:
        output = sandbox.stdout.read()
        sandbox.wait()
        if sandbox.returncode != 0:
            raise RuntimeError(f"security probe Sandbox exited with code {sandbox.returncode}")
        lines = [line for line in output.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("security probe Sandbox produced no output")
        evidence = json.loads(lines[-1])
        evidence["sandbox_id"] = sandbox_id
        evidence["outbound_domain_allowlist"] = _sandbox_options(gateway_url, probe=True)[
            "outbound_domain_allowlist"
        ]
        return evidence
    finally:
        sandbox.detach()


@app.function(image=image, schedule=modal.Period(minutes=5), timeout=60)
def reconcile_telegram_sandbox():
    """Keep exactly one named, allowlisted Telegram Sandbox running."""
    return _ensure_telegram_sandbox()


@app.function(image=image, timeout=PROBE_TIMEOUT_SECONDS + 60)
def launch_security_probe():
    """Run the existing isolation checks inside a short-lived Sandbox."""
    return _run_security_probe()


@app.local_entrypoint()
def main(probe: bool = False):
    """Reconcile the deployed Sandbox, or launch the safe egress probe."""
    function_name = "launch_security_probe" if probe else "reconcile_telegram_sandbox"
    function = modal.Function.from_name(APP_NAME, function_name)
    print(json.dumps(function.remote(), sort_keys=True))
