"""SN60 execution-backend policy.

Production rounds use the attested TEE so a miner's sealed credential is the
only inference credential available to its agent.  The local Docker sandbox is
an explicit development mode, never an accidental production fallback.
"""

from __future__ import annotations

import os

EXECUTION_BACKEND_ENV = "KATA_SN60_EXECUTION_BACKEND"
LEGACY_TEE_ENV = "KATA_SN60_USE_TEE_ROOM"
_BACKENDS = frozenset({"tee", "sandbox"})


def resolve_execution_backend() -> str:
    """Return ``tee`` by default, or an explicitly selected development backend."""
    configured = os.environ.get(EXECUTION_BACKEND_ENV, "").strip().lower()
    if configured:
        if configured not in _BACKENDS:
            raise ValueError(
                f"{EXECUTION_BACKEND_ENV} must be one of: {', '.join(sorted(_BACKENDS))}."
            )
        return configured

    # Preserve existing deployments during migration.  An explicitly supplied
    # legacy false value means the operator deliberately selected the sandbox;
    # new deployments should use KATA_SN60_EXECUTION_BACKEND instead.
    legacy = os.environ.get(LEGACY_TEE_ENV, "").strip().lower()
    if legacy:
        return "tee" if legacy in {"1", "true", "yes", "on"} else "sandbox"
    return "tee"


def tee_execution_enabled() -> bool:
    return resolve_execution_backend() == "tee"
