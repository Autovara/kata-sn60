from __future__ import annotations

import hashlib
import json
import os
import re
import secrets

from kata_sn60.sn60_bitsec import (
    load_sn60_benchmark_project_keys,
    resolve_sn60_sandbox_source,
)

SN60_PROJECT_SAMPLE_SIZE_ENV = "KATA_SN60_PROJECT_SAMPLE_SIZE"
SN60_PROJECT_SAMPLE_SECRET_ENV = "KATA_SN60_PROJECT_SAMPLE_SECRET"
SN60_TEE_IMAGE_DIGESTS_JSON_ENV = "KATA_SN60_TEE_IMAGE_DIGESTS_JSON"

# The sealed room accepts a project only when its digest map (KATA_SN60_TEE_IMAGE_DIGESTS_JSON)
# has a well-formed image digest for it (see deploy/sn60-runner/tee_profile.py). The engine-side
# project selector must apply the SAME test BEFORE sampling, so a challenge can never pick a project
# the room has no digest for -- that project would 500 mid-round and wrongly close the candidate.
_SN60_IMAGE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def parse_room_runnable_project_keys_from_env() -> set[str] | None:
    """Project keys the sealed room can run, from the SAME digest map the room enforces.

    ``None`` only when ``KATA_SN60_TEE_IMAGE_DIGESTS_JSON`` is entirely unset (the selector then
    keeps its legacy, unconstrained behaviour). A present-but-empty value (``""``/``{}``/all
    malformed) is a fail-closed error, never a silent pass. Digest match is byte-exact (no
    whitespace tolerance) so this accepts exactly what the room accepts.
    """
    raw = os.environ.get(SN60_TEE_IMAGE_DIGESTS_JSON_ENV)
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        raise ValueError(
            f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV} is set but empty; the sealed room can run no "
            "projects. Unset it to skip the runnable gate, or provide a non-empty digest map."
        )
    try:
        digests = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV} must be a JSON object of "
            "project_key -> sha256:<digest>."
        ) from exc
    if not isinstance(digests, dict):
        raise ValueError(
            f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV} must be a JSON object of "
            "project_key -> sha256:<digest>."
        )
    runnable = {
        str(key)
        for key, digest in digests.items()
        if isinstance(digest, str) and _SN60_IMAGE_DIGEST_RE.fullmatch(digest)
    }
    if not runnable:
        raise ValueError(
            f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV} contains no well-formed sha256:<digest> entries; "
            "the sealed room can run no projects."
        )
    return runnable


def parse_sn60_project_keys_from_env() -> list[str]:
    configured = os.environ.get("KATA_SN60_PROJECT_KEYS", "")
    return [part.strip() for part in configured.split(",") if part.strip()]


def parse_sn60_project_sample_size_from_env() -> int | None:
    value = os.environ.get(SN60_PROJECT_SAMPLE_SIZE_ENV, "")
    if not value.strip():
        return None
    try:
        sample_size = int(value.strip())
    except ValueError as exc:
        raise ValueError(f"{SN60_PROJECT_SAMPLE_SIZE_ENV} must be a positive integer.") from exc
    if sample_size <= 0:
        raise ValueError(f"{SN60_PROJECT_SAMPLE_SIZE_ENV} must be greater than 0.")
    return sample_size


def resolve_sn60_project_keys(
    *,
    configured_keys: list[str] | None,
    sandbox_root: str | None,
    benchmark_file: str | None,
    sandbox_commit: str | None,
    king_artifact_hash: str | None = None,
    candidate_artifact_hash: str | None = None,
    candidate_submission_id: str | None = None,
) -> list[str]:
    room_runnable = parse_room_runnable_project_keys_from_env()
    explicit_keys = configured_keys or parse_sn60_project_keys_from_env()
    if explicit_keys:
        if room_runnable is not None:
            unpinned = [key for key in explicit_keys if key not in room_runnable]
            if unpinned:
                raise ValueError(
                    "configured SN60 project keys have no pinned room image digest in "
                    f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV}: {', '.join(unpinned)}."
                )
        return explicit_keys
    sandbox_source = resolve_sn60_sandbox_source(
        sandbox_root=sandbox_root,
        benchmark_file=benchmark_file,
        sandbox_commit=sandbox_commit,
        scorer_version="ScaBenchScorerV2",
    )
    benchmark_keys = load_sn60_benchmark_project_keys(sandbox_source)
    if room_runnable is not None:
        # Constrain to the room's pinned set BEFORE sampling, so a sampled challenge can never
        # select a project the room has no digest for. Fail-closed and order-preserving.
        benchmark_keys = [key for key in benchmark_keys if key in room_runnable]
        if not benchmark_keys:
            raise ValueError(
                "no SN60 benchmark project is pinned in "
                f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV}; the sealed room can run none of them."
            )
    sample_size = parse_sn60_project_sample_size_from_env()
    if sample_size is None or sample_size >= len(benchmark_keys):
        return benchmark_keys
    sample_secret = os.environ.get(SN60_PROJECT_SAMPLE_SECRET_ENV, "")
    if not sample_secret.strip():
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SECRET_ENV} must be set when "
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV} narrows the SN60 benchmark."
        )
    return sample_sn60_project_keys(
        benchmark_keys,
        sample_size=sample_size,
        sample_secret=sample_secret.strip(),
        sample_nonce=secrets.token_hex(16),
        king_artifact_hash=king_artifact_hash or "",
        candidate_artifact_hash=candidate_artifact_hash or "",
        candidate_submission_id=candidate_submission_id or "",
    )


def sample_sn60_project_keys(
    project_keys: list[str],
    *,
    sample_size: int,
    sample_secret: str,
    sample_nonce: str,
    king_artifact_hash: str,
    candidate_artifact_hash: str,
    candidate_submission_id: str,
) -> list[str]:
    if sample_size <= 0:
        raise ValueError("SN60 project sample size must be greater than 0.")
    ordered_keys = list(dict.fromkeys(project_keys))
    if sample_size >= len(ordered_keys):
        return ordered_keys
    seed = "\x1f".join(
        [
            sample_secret,
            sample_nonce,
            king_artifact_hash,
            candidate_artifact_hash,
            candidate_submission_id,
        ]
    )
    ordered = sorted(
        ordered_keys,
        key=lambda key: hashlib.sha256(f"{seed}\x1f{key}".encode()).hexdigest(),
    )
    return ordered[:sample_size]
