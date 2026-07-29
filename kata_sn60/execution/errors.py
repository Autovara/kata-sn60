"""Execution failures owned by the SN60 validator or sealed-room infrastructure."""

from __future__ import annotations


class Sn60ExecutionInfrastructureError(RuntimeError):
    """The validator could not obtain a trustworthy agent result.

    This is deliberately distinct from an attested agent report whose ``success`` field is false.
    Only the latter is evidence about a submission.  Transport, room, Docker-daemon, and
    attestation failures must abort the challenge so the generic competition driver returns the
    entrant to ``kata:pending`` instead of scoring infrastructure trouble against it.
    """
