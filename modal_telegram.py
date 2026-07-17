"""Deploy the isolated Telegram reference slot and its safe security probe."""

import json
from pathlib import Path

import modal

ROOT = Path(__file__).parent
LOCAL_GLC = ROOT / "glc"

app = modal.App("glc-adapter-telegram")


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
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "httpx>=0.27",
        "pydantic>=2.6",
        "pyyaml>=6.0",
        "websockets>=12.0",
    )
    .env({"GLC_SLOT": "telegram"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc", ignore=_ignore)
)

channel_secret = modal.Secret.from_name("telegram-channel-secret")
identity_secret = modal.Secret.from_name("telegram-slot-identity")
gateway_url_secret = modal.Secret.from_name("telegram-gateway-url")


@app.function(
    image=image,
    secrets=[channel_secret, identity_secret, gateway_url_secret],
    cpu=0.25,
    memory=256,
    min_containers=0,
    max_containers=1,
    timeout=600,
)
async def telegram_adapter():
    from glc.isolation.telegram_runtime import run

    await run()


@app.function(
    image=image,
    secrets=[channel_secret, identity_secret, gateway_url_secret],
    cpu=0.25,
    memory=256,
    timeout=120,
)
async def security_probe():
    from glc.isolation.telegram_runtime import security_probe as probe

    return await probe()


@app.local_entrypoint()
def main():
    """Invoke the safe probe; output contains booleans and status codes only."""
    print(json.dumps(security_probe.remote(), sort_keys=True))
