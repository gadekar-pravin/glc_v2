"""Loads channels.yaml and policy.yaml. Resolves user-config directory.

The default config lives in `~/.glc/`. Override with GLC_CONFIG_DIR for
tests and CI. The directory is created on import if missing.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CONFIG_DIR = Path(os.getenv("GLC_CONFIG_DIR", str(DEFAULT_DIR)))
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
INSTALL_TOKEN_ENV = "GLC_INSTALL_TOKEN"

# Packaged defaults shipped with glc (under the policy/ subpackage).
PACKAGED_POLICY = Path(__file__).parent / "policy" / "policy.yaml"
PACKAGED_CHANNELS = Path(__file__).parent / "channels.yaml"


def policy_yaml_path() -> Path:
    user = CONFIG_DIR / "policy.yaml"
    return user if user.exists() else PACKAGED_POLICY


def channels_yaml_path() -> Path:
    user = CONFIG_DIR / "channels.yaml"
    return user if user.exists() else PACKAGED_CHANNELS


def load_channels() -> dict:
    p = channels_yaml_path()
    if not p.exists():
        return {"channels": {}}
    return yaml.safe_load(p.read_text()) or {"channels": {}}


def install_token_path() -> Path:
    return CONFIG_DIR / "install_token"


def get_or_create_install_token() -> str:
    """Return the gateway control token.

    Production receives the token from its gateway-only container Secret and
    must never fall back to shared storage. Local development retains the
    original persisted-token workflow for CLI compatibility.
    """
    configured = os.getenv(INSTALL_TOKEN_ENV)
    if configured is not None:
        token = configured.strip()
        if not token:
            raise RuntimeError(f"{INSTALL_TOKEN_ENV} is configured but empty")
        return token

    if os.getenv("GLC_ENV", "").strip().lower() == "production":
        raise RuntimeError(f"{INSTALL_TOKEN_ENV} is required in production")

    p = install_token_path()
    if p.exists():
        return p.read_text().strip()
    import secrets

    tok = secrets.token_urlsafe(32)
    p.write_text(tok)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return tok
