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


@pytest.fixture(autouse=True)
def _allow_unverified_sandbox_mirrors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let tests score against the hermetic sandbox mirrors they build in ``tmp_path``.

    Those mirrors have neither a ``.git`` directory nor a ``SANDBOX_MANIFEST.json``, so the lane
    cannot establish which upstream commit they are. Production refuses that outright; a test that
    is deliberately constructing a fake tree has to be able to say "yes, I know".

    It is opt-in rather than the default because of what the default used to be. The lane used to
    accept ANY tree without ``.git`` and record whatever commit the caller claimed -- so 62 tests
    passed here while, on the day the sandbox moved from a clone into this repository, production
    would have started publishing unverified commits and nothing would have failed.

    Setting it here rather than in the code keeps that distinction where it belongs: "I could not
    check" must not be spelled the same way as "I checked". The refusal itself, and the verified
    path, are covered by ``tests/test_sn60_vendored_sandbox.py``, which unsets this.
    """
    monkeypatch.setenv("KATA_SN60_ALLOW_UNVERIFIED_SANDBOX", "1")
