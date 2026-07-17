"""Reproducible base images for Modal deployment definitions."""

from pathlib import Path

import modal

PROJECT_ROOT = Path(__file__).parent.resolve()

# Modal executes registry images on linux/amd64. Keep the human-readable tag for
# maintenance, but bind it to the immutable architecture-specific manifest.
PYTHON_BASE_IMAGE = (
    "docker.io/library/python:3.11.12-slim-bookworm@"
    "sha256:df52c7d12cc5bd9b0437abbf295ef7eb78f68948e906d68cec8741a585bb6df3"
)
UV_VERSION = "0.8.11"


def locked_runtime_image(*, only_group: str | None = None) -> modal.Image:
    """Build an image from the committed uv lockfile without re-resolving it."""
    dependency_selection = f"--only-group={only_group}" if only_group else "--no-dev"
    return modal.Image.from_registry(PYTHON_BASE_IMAGE).uv_sync(
        str(PROJECT_ROOT),
        frozen=True,
        extra_options=dependency_selection,
        uv_version=UV_VERSION,
    )
