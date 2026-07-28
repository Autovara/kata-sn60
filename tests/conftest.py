from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _default_local_execution_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default kata-sn60 tests to the local (sandbox) execution backend.

    Production defaults to the attested TEE, which requires every submission to
    ship a ``sealed_inference_key``. Most tests exercise backend-independent
    screening / challenge / promotion logic with keyless fixture bundles, so
    default them to the local backend. TEE-specific tests override this by
    setting or deleting ``KATA_SN60_EXECUTION_BACKEND`` themselves.
    """
    monkeypatch.setenv("KATA_SN60_EXECUTION_BACKEND", "sandbox")


@pytest.fixture(autouse=True)
def _no_docker_image_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not probe ``docker`` for project images during tests.

    Project selection defaults to verifying that each project's ``ghcr.io/bitsec-ai`` image can run
    before selecting it. That is right in a deployment and wrong in a test: the fixture project keys
    name images that do not exist, and the probe would shell out to a docker daemon and the network.
    Production is unaffected -- it pins ``KATA_SN60_TEE_IMAGE_DIGESTS_JSON``, which supersedes the
    probe entirely. Tests that exercise the probe set this themselves.
    """
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "false")
