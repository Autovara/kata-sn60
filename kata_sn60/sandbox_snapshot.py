"""Identity and integrity of the vendored SN60 sandbox.

SN60 scoring is defined by the upstream Bitsec sandbox. It used to be a **clone** on the deployment
host at `/srv/sandbox`, located through `KATA_SN60_SANDBOX_ROOT`, and the lane established which
commit it was scoring by reading that clone's `.git`. This module exists because the tree now ships
with the plugin, the way SN22's does, and a `git archive` tree has no `.git` to read.

**What replaced the `.git` check, and why it had to.** `resolve_sandbox_source` used to do this:

    if (sandbox_root / ".git").exists():
        verify the checked-out commit against the pin      # provenance PROVEN
    else:
        resolved_commit = expected_commit                  # provenance ASSERTED

The second branch trusts the caller's claim and checks nothing. It was written for unit tests and
"hermetic scorer mirrors", which is reasonable in itself -- but a vendored tree takes that branch
too. Moving the sandbox into this repository without replacing it would have turned every published
result's commit from a verified fact into an unchecked assertion, while looking like a pure
relocation. So the vendored tree carries a manifest of per-file digests instead, and verification is
structural: a changed file, a missing file, an *extra* file, a symlink or an escaping path are all
findings.

The generic machinery lives in `kata.core.tree_snapshot`, not here. SN22 already had it, and a
second copy of security-critical verification logic that must agree with the first is the mistake
`kata/core/execution_backend.py` was created to undo.

Re-pinning at a new upstream commit is a deliberate act by a reviewer -- re-vendor with
`tools/vendor_sandbox.py write`, never as a side effect of a build. A build that regenerates its own
pin can never detect drift.
"""

from __future__ import annotations

import os
from pathlib import Path

from kata.core.tree_snapshot import (
    SnapshotError,
    SnapshotIdentity,
    compute_manifest,
    load_manifest,
    require_intact,
    verify_snapshot,
)

#: The audited upstream. Single source of truth for the plugin, the provenance record and the
#: manifest, so no two of them can disagree about which tree was scored.
UPSTREAM_REPO = "https://github.com/Bitsec-AI/sandbox"

MANIFEST_NAME = "SANDBOX_MANIFEST.json"

#: Where the vendored tree lives inside this repository.
VENDORED_DIRNAME = "sandbox"


def upstream_commit() -> str:
    """The pinned commit, read from the plugin's single declaration.

    Imported lazily to keep this module importable from the vendoring tool before the plugin package
    is fully importable, and to avoid a cycle: ``sn60_bitsec`` uses this module for verification.
    """
    from kata_sn60.sn60_bitsec import DEFAULT_SANDBOX_COMMIT

    return DEFAULT_SANDBOX_COMMIT


def identity() -> SnapshotIdentity:
    return SnapshotIdentity(
        repo=UPSTREAM_REPO, commit=upstream_commit(), manifest_name=MANIFEST_NAME
    )


def vendored_root() -> Path:
    """The vendored sandbox tree that ships with this plugin.

    ``KATA_SN60_VENDORED_SANDBOX_ROOT`` exists for the installed layout, where the trusted installer
    places the tree beside the package rather than inside the wheel. Read once, here, so exactly one
    place decides which tree the lane scores against.
    """
    override = os.environ.get("KATA_SN60_VENDORED_SANDBOX_ROOT")
    if override and override.strip():
        return Path(override.strip()).expanduser().resolve()
    return (Path(__file__).resolve().parent.parent / VENDORED_DIRNAME).resolve()


def is_vendored(root: Path) -> bool:
    """Whether ``root`` is a manifest-pinned vendored tree rather than a git clone.

    Asked of the path actually in use, not of configuration: an operator may still point the lane at
    a clone, and that must keep working exactly as before.
    """
    return (Path(root) / MANIFEST_NAME).is_file()


def verify(root: Path | None = None):
    root = Path(root) if root is not None else vendored_root()
    return verify_snapshot(root, identity())


def require_verified(root: Path | None = None) -> str:
    """Verify the tree and return its digest, or raise ``SnapshotError``. Fails closed."""
    root = Path(root) if root is not None else vendored_root()
    return require_intact(root, identity())


def manifest(root: Path | None = None) -> dict:
    root = Path(root) if root is not None else vendored_root()
    return load_manifest(root, identity())


def build_manifest(root: Path | None = None) -> dict:
    root = Path(root) if root is not None else vendored_root()
    return compute_manifest(root, identity())


def sandbox_identity(root: Path | None = None) -> dict:
    """The three fields every provenance record quotes about the sandbox."""
    document = manifest(root)
    return {
        "sandbox_repo": UPSTREAM_REPO,
        "sandbox_commit": upstream_commit(),
        "sandbox_tree_sha256": str(document.get("tree_sha256") or ""),
    }


__all__ = [
    "MANIFEST_NAME",
    "UPSTREAM_REPO",
    "VENDORED_DIRNAME",
    "SnapshotError",
    "build_manifest",
    "identity",
    "is_vendored",
    "manifest",
    "require_verified",
    "sandbox_identity",
    "upstream_commit",
    "vendored_root",
    "verify",
]
