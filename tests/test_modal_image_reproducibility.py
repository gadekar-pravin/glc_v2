"""Structural regression tests for reproducible Modal image definitions."""

from pathlib import Path

import modal

import modal_images


class _RecordingImage:
    def __init__(self) -> None:
        self.sync_args: tuple[tuple[object, ...], dict[str, object]] | None = None

    def uv_sync(self, *args: object, **kwargs: object) -> "_RecordingImage":
        self.sync_args = (args, kwargs)
        return self


def _record_image_build(monkeypatch, *, only_group: str | None = None) -> _RecordingImage:
    recording_image = _RecordingImage()
    registry_references: list[str] = []

    def from_registry(reference: str) -> _RecordingImage:
        registry_references.append(reference)
        return recording_image

    monkeypatch.setattr(modal.Image, "from_registry", from_registry)
    result = modal_images.locked_runtime_image(only_group=only_group)

    assert result is recording_image
    assert registry_references == [modal_images.PYTHON_BASE_IMAGE]
    return recording_image


def test_base_image_is_pinned_to_expected_linux_amd64_digest():
    assert modal_images.PYTHON_BASE_IMAGE == (
        "docker.io/library/python:3.11.12-slim-bookworm@"
        "sha256:df52c7d12cc5bd9b0437abbf295ef7eb78f68948e906d68cec8741a585bb6df3"
    )


def test_gateway_image_syncs_production_dependencies_from_lockfile(monkeypatch):
    image = _record_image_build(monkeypatch)

    assert image.sync_args == (
        (str(modal_images.PROJECT_ROOT),),
        {
            "frozen": True,
            "extra_options": "--no-dev",
            "uv_version": "0.8.11",
        },
    )


def test_telegram_image_syncs_only_its_locked_runtime_group(monkeypatch):
    image = _record_image_build(monkeypatch, only_group="telegram-runtime")

    assert image.sync_args == (
        (str(modal_images.PROJECT_ROOT),),
        {
            "frozen": True,
            "extra_options": "--only-group=telegram-runtime",
            "uv_version": "0.8.11",
        },
    )


def test_deployment_definitions_use_only_the_locked_image_helper():
    root = Path(__file__).parents[1]
    gateway_source = (root / "modal_app.py").read_text()
    telegram_source = (root / "modal_telegram.py").read_text()

    assert "locked_runtime_image()" in gateway_source
    assert 'locked_runtime_image(only_group="telegram-runtime")' in telegram_source
    for source in (gateway_source, telegram_source):
        assert "debian_slim" not in source
        assert "pip_install" not in source
