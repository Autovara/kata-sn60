"""SN60 execution-backend policy.

Production challenges use the attested TEE so a miner's sealed credential is the
only inference credential available to its agent.  The local Docker sandbox is
an explicit development mode, never an accidental production fallback.
"""

from __future__ import annotations

from kata.core.execution_backend import ExecutionBackendPolicy

EXECUTION_BACKEND_ENV = "KATA_SN60_EXECUTION_BACKEND"
_BACKENDS = frozenset({"tee", "sandbox"})

#: The rule itself lives in core, subnet-neutral. SN60 supplies only what is genuinely its own:
#: the variable name, the permitted values, and which one is safe when nothing is configured.
#:
#: This replaced a byte-identical copy of the same logic in the other subnet. A fix to one -- for
#: instance tightening what counts as an acceptable value -- silently did not reach the other.
_POLICY = ExecutionBackendPolicy(EXECUTION_BACKEND_ENV, _BACKENDS, "tee")


def resolve_execution_backend() -> str:
    """Return ``tee`` by default, or an explicitly selected development backend."""
    return _POLICY.resolve()


def tee_execution_enabled() -> bool:
    return _POLICY.is_selected("tee")
