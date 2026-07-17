"""A2 regression tests for configuration and operational read endpoints."""

from __future__ import annotations

import pytest

PROTECTED_READS = [
    "/v1/embedders",
    "/v1/cost/by_agent",
    "/v1/providers",
    "/v1/capabilities",
    "/v1/status",
    "/v1/routers",
    "/v1/calls",
]


@pytest.mark.parametrize("path", PROTECTED_READS)
@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        ({}, 401),
        ({"Authorization": "Basic abc"}, 401),
        ({"Authorization": "Bearer "}, 401),
        ({"Authorization": "Bearer incorrect"}, 403),
    ],
)
def test_config_reads_reject_invalid_auth(app_client, path, headers, expected_status):
    response = app_client.get(path, headers=headers)

    assert response.status_code == expected_status
    if expected_status == 401:
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.json() == {"detail": "missing bearer token (Authorization: Bearer <install_token>)"}
    else:
        assert response.json() == {"detail": "install token mismatch"}


@pytest.mark.parametrize("path", PROTECTED_READS)
def test_config_reads_accept_install_token(app_client, install_auth, path):
    response = app_client.get(path, headers=install_auth)

    assert response.status_code == 200
