"""Sandbox execution glue for the renaming-invariance canary (Layer 2).

The benchmark project source lives inside the sandbox's project images
(``ghcr.io/bitsec-ai/<project>``) at ``/app/project_code``. This module reads that
source out of the image (read-only; it never modifies the sandbox), renames the
distinctive identifiers, and lets the agent be run against a renamed copy volume-mounted
over the original path -- a runtime override that leaves the sandbox image untouched.

The pure rename/compare logic lives in ``mutation_canary``; this module is the thin,
side-effecting I/O layer (docker cp + file walk) so the canary decision stays unit-tested.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from kata_sn60.mutation_canary import rename_solidity_identifiers

# Source extensions we rename. Renaming is identifier-based, so it is language-agnostic
# enough to break fingerprints in Solidity/Rust/Cairo/Vyper benchmark projects.
CANARY_SOURCE_EXTS: frozenset[str] = frozenset({".sol", ".rs", ".cairo", ".vy"})

# Where the sandbox images keep the project under test.
IMAGE_PROJECT_SOURCE_PATH = "/app/project_code"


def bitsec_project_image(project_key: str) -> str:
    return f"ghcr.io/bitsec-ai/{project_key}:latest"


def extract_project_source(
    image: str, dest_dir: Path, *, source_path: str = IMAGE_PROJECT_SOURCE_PATH
) -> Path:
    """Copy the project source out of an image into ``dest_dir`` (read-only on the image).

    Uses ``docker create`` + ``docker cp`` so nothing runs and the image is unchanged.
    Returns the directory containing the copied source.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    created = subprocess.run(
        ["docker", "create", image], capture_output=True, text=True, check=True
    )
    container_id = created.stdout.strip()
    try:
        subprocess.run(
            ["docker", "cp", f"{container_id}:{source_path}", str(dest_dir / "project_code")],
            capture_output=True,
            text=True,
            check=True,
        )
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True, text=True)
    return dest_dir / "project_code"


def rename_source_tree(src_dir: Path, dest_dir: Path, *, salt: str = "canary") -> dict[str, str]:
    """Copy ``src_dir`` to ``dest_dir``, renaming distinctive identifiers in source files.

    Non-source files are copied verbatim. Returns the merged original->renamed identifier
    map across all files (renaming is consistent within each file).
    """
    combined: dict[str, str] = {}
    for path in sorted(src_dir.rglob("*")):
        rel = path.relative_to(src_dir)
        target = dest_dir / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.lower() in CANARY_SOURCE_EXTS:
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                target.write_bytes(path.read_bytes())
                continue
            renamed, mapping = rename_solidity_identifiers(content, salt=salt)
            target.write_text(renamed, encoding="utf-8")
            combined.update(mapping)
        else:
            target.write_bytes(path.read_bytes())
    return combined
