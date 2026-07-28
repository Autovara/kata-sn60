"""Which benchmark projects a SN60 challenge runs, and how many replicas of each.

This is the ONLY place SN60 project selection is decided. It used to be decided twice -- here and
again in the validator resident -- which meant the resident could hand down a project set the
plugin's own gates would never have chosen. The resident now passes nothing and asks nothing; it
starts a challenge and this module answers.

Selection has three modes, in precedence order:

1. **Explicit** -- ``KATA_SN60_PROJECT_KEYS`` (or keys passed on the challenge command). Run exactly
   these.
2. **Mixed** -- ``KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS`` always run, and the rest of
   ``KATA_SN60_PROJECT_SAMPLE_SIZE`` is sampled from what is left.
3. **Sampled** -- ``KATA_SN60_PROJECT_SAMPLE_SIZE`` projects drawn from the runnable benchmark.

Every mode is filtered to projects that can actually RUN first. Runnability has two sources and the
sealed room's pinned digest map wins: selecting a project the room has no digest for makes the room
return HTTP 500 mid-round, which closes an innocent candidate as invalid.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from kata_sn60.sn60_bitsec import (
    load_sn60_benchmark_project_keys,
    resolve_sn60_sandbox_source,
)

SN60_PROJECT_KEYS_ENV = "KATA_SN60_PROJECT_KEYS"
SN60_FIXED_PROJECT_KEYS_ENV = "KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS"
SN60_PROJECT_SAMPLE_SIZE_ENV = "KATA_SN60_PROJECT_SAMPLE_SIZE"
SN60_PROJECT_SAMPLE_SECRET_ENV = "KATA_SN60_PROJECT_SAMPLE_SECRET"
SN60_REPLICAS_PER_PROJECT_ENV = "KATA_SN60_REPLICAS_PER_PROJECT"
SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES_ENV = "KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES"
SN60_TEE_IMAGE_DIGESTS_JSON_ENV = "KATA_SN60_TEE_IMAGE_DIGESTS_JSON"

#: A docker probe that hangs must not hang the round; it is only a pre-check.
SN60_PROJECT_IMAGE_CHECK_TIMEOUT_SECONDS = 15.0

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


@dataclass(frozen=True)
class ProjectImageAvailability:
    project_key: str
    image: str
    runnable: bool
    source: str
    detail: str = ""


def parse_sn60_project_keys_from_env() -> list[str]:
    configured = os.environ.get(SN60_PROJECT_KEYS_ENV, "")
    return [part.strip() for part in configured.split(",") if part.strip()]


def parse_sn60_fixed_project_keys_from_env() -> list[str]:
    """Projects that must appear in EVERY challenge, with the remainder of the sample drawn around
    them. Empty (the default) means the whole set is sampled."""
    configured = os.environ.get(SN60_FIXED_PROJECT_KEYS_ENV, "")
    return [part.strip() for part in configured.split(",") if part.strip()]


def parse_sn60_replicas_per_project_from_env() -> int | None:
    """Replicas to score per project, from the deployment env.

    ``None`` when unset, so the caller applies its own default; a set value must be a positive
    integer rather than silently degrading to one replica.
    """
    value = os.environ.get(SN60_REPLICAS_PER_PROJECT_ENV, "")
    if not value.strip():
        return None
    try:
        replicas = int(value.strip())
    except ValueError as exc:
        raise ValueError(f"{SN60_REPLICAS_PER_PROJECT_ENV} must be a positive integer.") from exc
    if replicas <= 0:
        raise ValueError(f"{SN60_REPLICAS_PER_PROJECT_ENV} must be greater than 0.")
    return replicas


def require_runnable_project_images_from_env() -> bool:
    """Whether to probe ``docker`` for each project image before selecting it.

    Only consulted when the room has no pinned digest map: the digest map is authoritative and
    needs no docker access, so it makes this flag moot.
    """
    value = os.environ.get(SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES_ENV, "true")
    return value.strip().lower() not in {"0", "false", "no", "off"}


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
    explicit_keys = configured_keys or parse_sn60_project_keys_from_env()
    fixed_keys = parse_sn60_fixed_project_keys_from_env()
    if explicit_keys:
        if fixed_keys and not configured_keys:
            raise ValueError(
                f"{SN60_FIXED_PROJECT_KEYS_ENV} cannot be combined with "
                f"{SN60_PROJECT_KEYS_ENV}; use one project-selection mode."
            )
        validate_project_images_are_runnable(explicit_keys)
        return list(explicit_keys)

    sandbox_source = resolve_sn60_sandbox_source(
        sandbox_root=sandbox_root,
        benchmark_file=benchmark_file,
        sandbox_commit=sandbox_commit,
        scorer_version="ScaBenchScorerV2",
    )
    benchmark_keys = load_sn60_benchmark_project_keys(sandbox_source)
    selectable_keys = resolve_selectable_project_keys(benchmark_keys)
    sample_size = parse_sn60_project_sample_size_from_env()
    sample_secret = os.environ.get(SN60_PROJECT_SAMPLE_SECRET_ENV, "")
    if fixed_keys:
        validate_fixed_project_selection(
            benchmark_keys=benchmark_keys,
            selectable_keys=selectable_keys,
            fixed_keys=fixed_keys,
            sample_size=sample_size,
            sample_secret=sample_secret,
        )
    else:
        validate_sampled_project_selection(
            benchmark_keys=benchmark_keys,
            selectable_keys=selectable_keys,
            sample_size=sample_size,
            sample_secret=sample_secret,
        )

    remaining_keys = [key for key in selectable_keys if key not in set(fixed_keys)]
    if sample_size is None or sample_size >= len(selectable_keys):
        return [*fixed_keys, *remaining_keys]
    if sample_size == len(fixed_keys):
        # The fixed keys fill the sample exactly; there is no room left to draw from.
        return list(fixed_keys)
    return [
        *fixed_keys,
        *sample_sn60_project_keys(
            remaining_keys,
            sample_size=sample_size - len(fixed_keys),
            sample_secret=sample_secret.strip(),
            sample_nonce=secrets.token_hex(16),
            king_artifact_hash=king_artifact_hash or "",
            candidate_artifact_hash=candidate_artifact_hash or "",
            candidate_submission_id=candidate_submission_id or "",
        ),
    ]


def resolve_selectable_project_keys(benchmark_keys: list[str]) -> list[str]:
    """The benchmark, narrowed to the projects that can actually run. Fail-closed.

    The room's pinned digest map takes precedence over the local docker probe and needs no docker
    access: a project the room has no digest for would 500 mid-round, so it must never be
    selectable, whatever the local docker daemon happens to have cached.
    """
    room_runnable = parse_room_runnable_project_keys_from_env()
    if room_runnable is not None:
        selectable_keys = [key for key in benchmark_keys if key in room_runnable]
        if not selectable_keys:
            raise ValueError(
                "None of the SN60 benchmark projects are pinned in "
                f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV}; the sealed room cannot run any of them. "
                "Pin their immutable image digests, or align the benchmark file to the pinned set."
            )
        return selectable_keys
    if not require_runnable_project_images_from_env():
        return list(benchmark_keys)
    availability = check_project_image_availability(benchmark_keys)
    selectable_keys = [
        key
        for key in benchmark_keys
        if availability.get(key, ProjectImageAvailability(key, "", False, "missing")).runnable
    ]
    if not selectable_keys:
        details = format_unavailable_project_images(availability)
        raise ValueError(
            "No SN60 benchmark projects have runnable Docker images. "
            "Preload the ghcr.io/bitsec-ai project images or fix registry access."
            + (f" Unavailable: {details}" if details else "")
        )
    return selectable_keys


def validate_project_images_are_runnable(project_keys: list[str]) -> None:
    """Reject explicitly named projects that cannot run. The digest map gates unconditionally; the
    docker probe stays behind its flag, because it needs a working local docker."""
    room_runnable = parse_room_runnable_project_keys_from_env()
    if room_runnable is not None:
        unpinned = [key for key in project_keys if key not in room_runnable]
        if unpinned:
            raise ValueError(
                "configured SN60 project keys have no pinned room image digest in "
                f"{SN60_TEE_IMAGE_DIGESTS_JSON_ENV}: {', '.join(unpinned)}."
            )
        return
    if not require_runnable_project_images_from_env():
        return
    availability = check_project_image_availability(project_keys)
    unavailable = {key: status for key, status in availability.items() if not status.runnable}
    if unavailable:
        raise ValueError(
            f"{SN60_PROJECT_KEYS_ENV} contains projects whose Docker images are not runnable: "
            f"{format_unavailable_project_images(unavailable)}"
        )


def validate_fixed_project_selection(
    *,
    benchmark_keys: list[str],
    selectable_keys: list[str],
    fixed_keys: list[str],
    sample_size: int | None,
    sample_secret: str,
) -> None:
    """Mixed mode only makes sense when the sample is strictly smaller than the benchmark and big
    enough to hold the fixed keys; anything else silently degenerates into a different mode."""
    if len(dict.fromkeys(fixed_keys)) != len(fixed_keys):
        raise ValueError(f"{SN60_FIXED_PROJECT_KEYS_ENV} must not contain duplicate project keys.")
    if sample_size is None:
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV} must be set when "
            f"{SN60_FIXED_PROJECT_KEYS_ENV} is used."
        )
    if sample_size >= len(benchmark_keys):
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV} must be smaller than the benchmark size when "
            f"{SN60_FIXED_PROJECT_KEYS_ENV} is used."
        )
    if len(fixed_keys) > sample_size:
        raise ValueError(
            f"{SN60_FIXED_PROJECT_KEYS_ENV} must not contain more keys than "
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV}."
        )
    if not sample_secret.strip():
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SECRET_ENV} must be set when "
            f"{SN60_FIXED_PROJECT_KEYS_ENV} is used."
        )
    missing = [key for key in fixed_keys if key not in set(benchmark_keys)]
    if missing:
        raise ValueError(
            f"{SN60_FIXED_PROJECT_KEYS_ENV} contains keys not present in the benchmark: "
            f"{', '.join(missing)}"
        )
    unavailable = [key for key in fixed_keys if key not in set(selectable_keys)]
    if unavailable:
        raise ValueError(
            f"{SN60_FIXED_PROJECT_KEYS_ENV} contains projects that cannot run: "
            f"{', '.join(unavailable)}. Pin their room image digests or fix registry access, "
            "or remove them from the fixed challenge set."
        )
    if sample_size > len(selectable_keys):
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV} asks for {sample_size} projects, but only "
            f"{len(selectable_keys)} benchmark projects can run."
        )


def validate_sampled_project_selection(
    *,
    benchmark_keys: list[str],
    selectable_keys: list[str],
    sample_size: int | None,
    sample_secret: str,
) -> None:
    if sample_size is None:
        return
    if sample_size >= len(benchmark_keys) and len(selectable_keys) == len(benchmark_keys):
        # Asking for the whole benchmark, and the whole benchmark is runnable: nothing is narrowed,
        # so no secret is needed and no shortfall is possible.
        return
    if sample_size > len(selectable_keys):
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV} asks for {sample_size} projects, but only "
            f"{len(selectable_keys)} benchmark projects can run."
        )
    if not sample_secret.strip():
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SECRET_ENV} must be set when "
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV} narrows the runnable SN60 benchmark."
        )


def check_project_image_availability(
    project_keys: list[str],
    *,
    run: Callable[..., subprocess.CompletedProcess] | None = None,
) -> dict[str, ProjectImageAvailability]:
    return {
        key: check_project_image_is_runnable(key, run=run)
        for key in list(dict.fromkeys(project_keys))
    }


def check_project_image_is_runnable(
    project_key: str,
    *,
    run: Callable[..., subprocess.CompletedProcess] | None = None,
) -> ProjectImageAvailability:
    run = run or subprocess.run
    image = bitsec_project_image(project_key)
    local = run_docker_check(["docker", "image", "inspect", image], run=run)
    if local.returncode == 0:
        return ProjectImageAvailability(project_key, image, True, "local")
    remote = run_docker_check(["docker", "manifest", "inspect", image], run=run)
    if remote.returncode == 0:
        return ProjectImageAvailability(project_key, image, True, "remote")
    detail = remote.stderr.strip() or remote.stdout.strip() or local.stderr.strip()
    return ProjectImageAvailability(project_key, image, False, "unavailable", detail)


def run_docker_check(
    command: list[str],
    *,
    run: Callable[..., subprocess.CompletedProcess],
) -> subprocess.CompletedProcess:
    """A missing or hung ``docker`` is an UNAVAILABLE image, not a crash: the caller decides whether
    an unavailable image is fatal, and it must get to make that decision."""
    try:
        return run(
            command,
            capture_output=True,
            text=True,
            timeout=SN60_PROJECT_IMAGE_CHECK_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, stdout="", stderr=str(exc))
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            command,
            124,
            stdout=exc.stdout or "",
            stderr=f"Docker image check timed out after {exc.timeout} seconds.",
        )


def format_unavailable_project_images(
    availability: dict[str, ProjectImageAvailability],
) -> str:
    parts = []
    for key, status in availability.items():
        if status.runnable:
            continue
        detail = f": {status.detail}" if status.detail else ""
        parts.append(f"{key} ({status.image}{detail})")
    return "; ".join(parts)


def bitsec_project_image(project_key: str) -> str:
    return f"ghcr.io/bitsec-ai/{project_key}:latest"


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
