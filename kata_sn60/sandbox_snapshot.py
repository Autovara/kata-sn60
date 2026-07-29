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

    Beside the package, in both layouts that matter: a source checkout has ``<repo>/sandbox``, and a
    deployed lane is installed with ``uv run --with-editable /srv/kata-sn<N>``, so the staged source
    tree is what lands on ``sys.path`` and the sibling is ``/srv/kata-sn<N>/sandbox``.

    The tree is NOT packaged into the wheel. It would have to live inside ``kata_sn60/`` to travel
    in one, and then pip byte-compiles it on install -- every ``__pycache__/*.pyc`` landing in the
    pinned tree as an unlisted file that fails verification on every round.

    ``KATA_SN60_VENDORED_SANDBOX_ROOT`` overrides both, for a layout neither fits. Read once, here,
    so exactly one place decides which tree the lane scores against.
    """
    override = os.environ.get("KATA_SN60_VENDORED_SANDBOX_ROOT")
    if override and override.strip():
        return Path(override.strip()).expanduser().resolve()
    return (Path(__file__).resolve().parent.parent / VENDORED_DIRNAME).resolve()


#: Working-tree states that make a clone unusable as evidence, keyed by the two-column code
#: ``git status --porcelain`` reports. Every one of them means the bytes on disk are not the bytes
#: the pinned commit names.
_CLONE_STATUS_REASONS = {
    "??": "untracked file in the clone",
    "!!": "ignored file in the clone",
}


def clone_findings(root: Path, *, expected_commit: str, runner=None) -> list[str]:
    """Everything that makes a git CLONE fail to prove the commit it claims.

    A vendored tree proves its commit from per-file digests. A clone was only ever asked for
    ``git rev-parse HEAD``, which answers "which commit is checked out" and NOT "is the working
    tree that commit" -- so a dirty ``executor.py``, a deleted benchmark, or an extra file all
    passed while the published result still named the pinned revision.

    The finding set is deliberately the same shape as ``verify_snapshot``'s: modified, missing,
    untracked, ignored and unexpected files are each a refusal. IGNORED files matter as much as
    untracked ones and are easy to forget -- ``.gitignore`` hides them from ``git status`` by
    default, yet Python will happily import a ``.pyc`` or a gitignored module sitting in the tree.
    (This is not hypothetical: a stray ``uv sync`` drops a fully importable ``.venv`` into the
    source that plain ``git status`` reports as nothing at all.)
    """
    import subprocess

    run = runner or subprocess.run
    root = Path(root)
    findings: list[str] = []

    def _git(*args: str) -> subprocess.CompletedProcess:
        return run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
        )

    head = _git("rev-parse", "HEAD")
    if head.returncode != 0:
        findings.append(f"cannot resolve HEAD: {(head.stderr or '').strip()}")
        return findings
    actual_commit = (head.stdout or "").strip()
    if actual_commit != expected_commit:
        findings.append(f"HEAD is {actual_commit}, expected {expected_commit}")

    # --ignored=matching lists ignored files individually rather than collapsing them into their
    # directory, so a single planted file is named instead of hidden behind a directory entry.
    status = _git(
        "status", "--porcelain", "--untracked-files=all", "--ignored=matching"
    )
    if status.returncode != 0:
        findings.append(f"cannot read working tree status: {(status.stderr or '').strip()}")
        return findings
    for line in (status.stdout or "").splitlines():
        if not line.strip():
            continue
        code, _, relative = line[:2], line[2:3], line[3:]
        reason = _CLONE_STATUS_REASONS.get(code)
        if reason is None:
            # Any other porcelain code is a tracked path that differs from HEAD: modified, deleted,
            # staged, renamed, copied or unmerged. Naming the raw code keeps the message honest
            # rather than guessing at a category.
            reason = f"tracked file differs from the pinned commit (status {code!r})"
        findings.append(f"{relative}: {reason}")
    return findings


def require_verified_clone(root: Path, *, expected_commit: str, runner=None) -> str:
    """Verify a clone and return its commit, or raise ``SnapshotError``. Fails closed."""
    findings = clone_findings(root, expected_commit=expected_commit, runner=runner)
    if findings:
        shown = "; ".join(findings[:20])
        more = f" (+{len(findings) - 20} more)" if len(findings) > 20 else ""
        raise SnapshotError(
            f"SN60 sandbox clone at {root} does not match pinned commit {expected_commit}: "
            f"{shown}{more}"
        )
    return expected_commit


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


def tree_sha256_for(root: Path | None = None) -> str:
    """The vendored tree's digest, or ``""`` when the tree is not a vendored one.

    Empty for a clone by design: a clone has no manifest, so there is no tree digest to bind a
    proxy image to. Callers treat empty as "cannot check this claim" rather than as a match.
    """
    root = Path(root) if root is not None else vendored_root()
    if not is_vendored(root):
        return ""
    try:
        return str(manifest(root).get("tree_sha256") or "")
    except SnapshotError:
        return ""


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
    "tree_sha256_for",
    "upstream_commit",
    "vendored_root",
    "verify",
]
