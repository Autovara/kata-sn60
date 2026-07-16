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
