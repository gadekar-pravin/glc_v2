"""
Modal deployment wrapper for the isolated GLC gateway.

This file changes NO application code. It only describes, for Modal:
  1. the container image to build,
  2. a persistent Volume for gateway config and databases,
  3. gateway-only install-token, provider, and credential-signing Secrets,
  4. per-slot identities used to authenticate isolated adapters,
  5. which object to serve  ->  glc.main:app.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file.
LOCAL_GLC = Path(__file__).parent / "glc"


def _gateway_ignore(path: Path) -> bool:
    """Keep untrusted slot implementations out of the gateway image."""
    try:
        parts = path.relative_to(LOCAL_GLC).parts
    except ValueError:
        return False
    if len(parts) >= 3 and parts[:2] == ("channels", "catalogue"):
        return True
    if len(parts) >= 4 and parts[:3] == ("voice", "stt", "providers"):
        return True
    if len(parts) >= 4 and parts[:3] == ("voice", "tts", "providers"):
        return parts[3] != "system_fallback"
    return False


# The image = a Linux box with Python 3.11, the same dependencies as
# pyproject.toml, the glc package copied in, and database paths pointed at the
# Volume mount so state survives the throwaway container filesystem.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "fastapi>=0.110",
        "uvicorn[standard]>=0.27",
        "httpx>=0.27",
        "python-dotenv>=1.0",
        "pydantic>=2.6",
        "jsonschema>=4.21",
        "pyyaml>=6.0",
        "pyjwt>=2.9",
        "websockets>=12.0",
        "twilio>=9.0",
    )
    .env(
        {
            # User policy/channels overrides live on the Volume. The control token
            # comes from the gateway-only glc-install-token Secret, never this path.
            "GLC_CONFIG_DIR": "/data/glc",
            # Disable API documentation and require the injected install token on
            # every HTTP route exposed by the public Modal deployment.
            "GLC_ENV": "production",
            # The three SQLite stores resolve their OWN env vars (default ~/.glc, the
            # throwaway container disk), NOT GLC_CONFIG_DIR. Point them at the Volume too
            # so the audit log, pairings, and worker-call ledger survive scale-to-zero.
            "GLC_GATEWAY_DB": "/data/glc/gateway.sqlite",
            "GLC_AUDIT_DB": "/data/glc/audit.sqlite",
            "GLC_PAIRING_DB": "/data/glc/pairings.sqlite",
        }
    )
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc", ignore=_gateway_ignore)
)

# A persistent Volume. Gateway databases and operator configuration live here
# and survive restarts and redeploys. Secrets are injected separately.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")
signing_secret = modal.Secret.from_name("glc-creds-signing-key")
telegram_identity_secret = modal.Secret.from_name("telegram-slot-identity")
install_token_secret = modal.Secret.from_name("glc-install-token")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret, signing_secret, telegram_identity_secret, install_token_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
    max_containers=1,  # SQLite single-use ledger requires one writer container
)
@modal.asgi_app()
def fastapi_app():
    """Serve the gateway without channel or external voice slot code."""
    import os

    # The gateway writes databases and operator configuration here, so the folder
    # must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the real glc_v1 app, imported as-is

    return web
