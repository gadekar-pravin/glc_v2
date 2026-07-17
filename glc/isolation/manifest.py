"""Load and validate the 22-slot least-privilege deployment manifest."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml

SUPPORTED_TOOLS = frozenset(
    {
        "llm.chat",
        "llm.chat.batch",
        "llm.vision",
        "llm.embed",
        "stt.transcribe",
        "tts.synthesize",
    }
)

PROVIDER_SECRET_KEYS = frozenset(
    {
        "GEMINI_API_KEY",
        "GITHUB_ACCESS_TOKEN",
        "GROQ_API_KEY",
        "NVIDIA_API_KEY",
        "CEREBRAS_API_KEY",
        "OPEN_ROUTER_API_KEY",
    }
)

GATEWAY_ONLY_SECRET_KEYS = frozenset({"GLC_INSTALL_TOKEN", "GLC_CREDS_SIGNING_KEY", "GLC_LEDGER_SIGNING_KEY"})

_PATH = Path(__file__).with_name("slots.yaml")


@dataclass(frozen=True)
class Slot:
    name: str
    kind: Literal["channel", "voice"]
    package: str
    runtime: str
    identity_env: str
    secret_name: str
    secret_keys: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    egress_domains: tuple[str, ...]
    cpu: float
    memory_mb: int
    timeout_seconds: int

    @property
    def is_channel(self) -> bool:
        return self.kind == "channel"


def _parse(raw: dict) -> Slot:
    required = {"name", "kind", "package", "runtime", "secret_name"}
    missing = required - raw.keys()
    if missing:
        raise RuntimeError(f"slot manifest entry is missing {sorted(missing)}")
    name = str(raw["name"])
    kind = str(raw["kind"])
    if kind not in {"channel", "voice"}:
        raise RuntimeError(f"slot {name!r} has invalid kind {kind!r}")
    identity_env = f"GLC_SLOT_IDENTITY_{name.upper()}"
    tools = tuple(raw.get("allowed_tools", ()))
    unsupported = set(tools) - SUPPORTED_TOOLS
    if unsupported:
        raise RuntimeError(f"slot {name!r} has unsupported tools {sorted(unsupported)}")
    secret_keys = tuple(raw.get("secret_keys", ()))
    gateway_only = GATEWAY_ONLY_SECRET_KEYS.intersection(secret_keys)
    if gateway_only:
        raise RuntimeError(f"slot {name!r} must not receive gateway-only secrets {sorted(gateway_only)}")
    if kind == "channel" and PROVIDER_SECRET_KEYS.intersection(secret_keys):
        raise RuntimeError(f"channel slot {name!r} must not receive LLM provider keys")
    egress_domains = tuple(raw.get("egress_domains", ()))
    if egress_domains:
        from glc.isolation.egress import validate_egress_domains

        egress_domains = validate_egress_domains(egress_domains)
    resources = raw.get("resources", {})
    return Slot(
        name=name,
        kind=kind,  # type: ignore[arg-type]
        package=str(raw["package"]),
        runtime=str(raw["runtime"]),
        identity_env=identity_env,
        secret_name=str(raw["secret_name"]),
        secret_keys=secret_keys,
        allowed_tools=tools,
        egress_domains=egress_domains,
        cpu=float(resources.get("cpu", 0.25)),
        memory_mb=int(resources.get("memory_mb", 256)),
        timeout_seconds=int(resources.get("timeout_seconds", 600)),
    )


@lru_cache(maxsize=1)
def all_slots() -> tuple[Slot, ...]:
    data = yaml.safe_load(_PATH.read_text()) or {}
    slots = tuple(_parse(entry) for entry in data.get("slots", ()))
    names = [slot.name for slot in slots]
    if len(slots) != 22:
        raise RuntimeError(f"expected 22 isolated slots, found {len(slots)}")
    if len(names) != len(set(names)):
        raise RuntimeError("slot manifest contains duplicate names")
    return slots


def get_slot(name: str) -> Slot:
    for slot in all_slots():
        if slot.name == name:
            return slot
    raise KeyError(f"unknown isolated slot {name!r}")


def channel_slots() -> tuple[Slot, ...]:
    return tuple(slot for slot in all_slots() if slot.kind == "channel")


def voice_slots() -> tuple[Slot, ...]:
    return tuple(slot for slot in all_slots() if slot.kind == "voice")
