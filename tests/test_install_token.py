"""Install-token storage boundary regression tests."""

from __future__ import annotations

import stat

import pytest

from glc.config import get_or_create_install_token, install_token_path


def test_configured_token_takes_precedence_without_creating_a_file(monkeypatch):
    monkeypatch.setenv("GLC_INSTALL_TOKEN", "gateway-secret-token")

    assert get_or_create_install_token() == "gateway-secret-token"
    assert not install_token_path().exists()


def test_configured_token_ignores_a_stale_legacy_file(monkeypatch):
    install_token_path().write_text("stale-file-token")
    monkeypatch.setenv("GLC_INSTALL_TOKEN", "active-secret-token")

    assert get_or_create_install_token() == "active-secret-token"
    assert install_token_path().read_text() == "stale-file-token"


@pytest.mark.parametrize("configured", [None, "", "   "])
def test_production_requires_a_nonempty_secret_even_with_a_legacy_file(monkeypatch, configured):
    install_token_path().write_text("legacy-token-must-not-be-used")
    monkeypatch.setenv("GLC_ENV", "production")
    if configured is None:
        monkeypatch.delenv("GLC_INSTALL_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GLC_INSTALL_TOKEN", configured)

    with pytest.raises(RuntimeError, match="GLC_INSTALL_TOKEN"):
        get_or_create_install_token()

    assert install_token_path().read_text() == "legacy-token-must-not-be-used"


def test_local_development_retains_file_backed_token(monkeypatch):
    monkeypatch.delenv("GLC_INSTALL_TOKEN", raising=False)
    monkeypatch.delenv("GLC_ENV", raising=False)

    first = get_or_create_install_token()
    second = get_or_create_install_token()

    assert second == first
    assert install_token_path().read_text() == first
    assert len(first) == 43
    assert stat.S_IMODE(install_token_path().stat().st_mode) == 0o600


def test_explicit_production_mode_is_authoritative(monkeypatch):
    install_token_path().write_text("legacy-token-must-not-be-used")
    monkeypatch.delenv("GLC_INSTALL_TOKEN", raising=False)
    monkeypatch.delenv("GLC_ENV", raising=False)

    with pytest.raises(RuntimeError, match="GLC_INSTALL_TOKEN"):
        get_or_create_install_token(production=True)

    assert get_or_create_install_token(production=False) == "legacy-token-must-not-be-used"
