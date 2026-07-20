"""Validation for SN60 competition challenge inputs.

Challenge labels become directory names in run artifacts, while project keys identify
trusted benchmark entries.  Validate both at the evaluator boundary so callers
cannot make colliding or escaping paths by bypassing the legacy challenge wrapper.
"""

from __future__ import annotations

import re

_SAFE_SUBMISSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def validate_challenge_candidates(candidates: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return validated candidates or raise before any artifact is written.

    Submission ids are used as directory segments and must therefore be a single,
    non-empty portable segment.  Their uniqueness prevents one candidate from
    overwriting another candidate's reports, progress, or challenge artifact.
    """
    if not candidates:
        raise ValueError("SN60 challenge requires at least one candidate.")

    seen_ids: set[str] = set()
    validated: list[tuple[str, str]] = []
    for submission_id, artifact_path in candidates:
        if not _SAFE_SUBMISSION_ID.fullmatch(submission_id):
            raise ValueError(
                "SN60 submission id must be a single path-safe identifier containing only "
                "letters, numbers, dots, underscores, or hyphens."
            )
        if submission_id in seen_ids:
            raise ValueError(f"Duplicate submission id in SN60 challenge: {submission_id}")
        if not artifact_path or not artifact_path.strip():
            raise ValueError(f"SN60 candidate '{submission_id}' has an empty artifact path.")
        seen_ids.add(submission_id)
        validated.append((submission_id, artifact_path))
    return validated
