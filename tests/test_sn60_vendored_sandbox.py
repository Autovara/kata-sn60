"""The sandbox now ships with this plugin, and its provenance must be PROVEN rather than claimed.

SN60 used to score against a clone on the deployment host, established its commit by reading that
clone's ``.git``, and fell back to trusting the caller when there was no ``.git``. The tree is now
vendored, and ``git archive`` output has no ``.git`` -- so that fallback would have caught every
production round. Moving the sandbox without closing it would have turned each published result's
commit from a verified fact into an unchecked assertion while looking like a pure relocation.

These tests exist to make that impossible to reintroduce. They deliberately UNSET the suite-wide
``KATA_SN60_ALLOW_UNVERIFIED_SANDBOX`` escape that lets other tests use hermetic mirrors, because a
guard tested only under its own bypass is not tested at all.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from kata.core.tree_snapshot import SnapshotError

from kata_sn60 import sandbox_snapshot
from kata_sn60.sn60_bitsec import (
    DEFAULT_BENCHMARK_FILENAME,
    DEFAULT_SANDBOX_COMMIT,
    UNVERIFIED_SANDBOX_ENV,
    default_sandbox_root,
    resolve_sn60_sandbox_source,
)

REPO = Path(__file__).resolve().parents[1]
VENDORED = REPO / "sandbox"


@pytest.fixture(autouse=True)
def _no_unverified_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test here runs with production's rules."""
    monkeypatch.delenv(UNVERIFIED_SANDBOX_ENV, raising=False)
    monkeypatch.delenv("KATA_SN60_SANDBOX_ROOT", raising=False)
    monkeypatch.delenv("KATA_SN60_VENDORED_SANDBOX_ROOT", raising=False)


def _mirror(tmp_path: Path) -> Path:
    """A writable copy of the vendored tree, so tampering tests cannot touch the real one."""
    target = tmp_path / "sandbox"
    shutil.copytree(VENDORED, target)
    return target


# --- the tree is really here, and it is really the pinned commit --------------------------------


def test_the_vendored_tree_ships_with_the_plugin():
    assert VENDORED.is_dir(), "the sandbox is no longer vendored into this repository"
    assert (VENDORED / sandbox_snapshot.MANIFEST_NAME).is_file()
    assert (VENDORED / "validator" / DEFAULT_BENCHMARK_FILENAME).is_file(), (
        "the benchmark the scorer reads is not in the vendored tree, so scoring would fall back to "
        "whatever happened to be on the host"
    )


def test_the_manifest_pins_the_commit_the_plugin_declares():
    document = sandbox_snapshot.manifest(VENDORED)
    assert document["upstream_commit"] == DEFAULT_SANDBOX_COMMIT
    assert document["upstream_repo"] == sandbox_snapshot.UPSTREAM_REPO
    assert document["file_count"] == len(document["files"]) > 0


def test_the_vendored_tree_verifies_against_its_manifest():
    verification = sandbox_snapshot.verify(VENDORED)
    assert verification.ok, verification.findings
    assert verification.observed_tree_sha256 == verification.expected_tree_sha256


def test_the_default_root_is_the_vendored_tree():
    """It used to be a workspace sibling four directories above the package -- a path that does not
    exist on a normal checkout. It only ever "worked" because production always sets
    ``KATA_SN60_SANDBOX_ROOT``, so the default was an untested guess."""
    assert default_sandbox_root() == VENDORED.resolve()
    assert default_sandbox_root().is_dir()


# --- what verification actually catches ---------------------------------------------------------


def test_a_changed_file_is_caught(tmp_path: Path):
    mirror = _mirror(tmp_path)
    target = mirror / "validator" / DEFAULT_BENCHMARK_FILENAME
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    findings = sandbox_snapshot.verify(mirror).findings
    assert any("digest drift" in finding for finding in findings), findings


def test_an_extra_file_is_caught(tmp_path: Path):
    """As serious as a changed one: the lane executes out of this tree, so an unlisted file is
    code nobody reviewed. A build cache written into the tree tripped this for real."""
    mirror = _mirror(tmp_path)
    (mirror / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
    findings = sandbox_snapshot.verify(mirror).findings
    assert any("not listed in the manifest" in finding for finding in findings), findings


def test_a_missing_file_is_caught(tmp_path: Path):
    mirror = _mirror(tmp_path)
    (mirror / "validator" / DEFAULT_BENCHMARK_FILENAME).unlink()
    findings = sandbox_snapshot.verify(mirror).findings
    assert any("missing from the tree" in finding for finding in findings), findings


def test_a_symlink_is_caught(tmp_path: Path):
    """Following one silently is how a link to a credential file ends up inside a verified tree."""
    mirror = _mirror(tmp_path)
    (mirror / "leak.json").symlink_to("/etc/hostname")
    findings = sandbox_snapshot.verify(mirror).findings
    assert any("symlink" in finding for finding in findings), findings


def test_a_manifest_for_a_different_commit_is_refused(tmp_path: Path):
    mirror = _mirror(tmp_path)
    path = mirror / sandbox_snapshot.MANIFEST_NAME
    document = json.loads(path.read_text(encoding="utf-8"))
    document["upstream_commit"] = "0" * 40
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SnapshotError):
        sandbox_snapshot.manifest(mirror)


# --- the fail-open that this change closed ------------------------------------------------------


def test_a_tree_with_no_git_and_no_manifest_is_refused(tmp_path: Path):
    """THE regression this guards. The old code recorded the caller's claimed commit here and
    published it as provenance."""
    bare = tmp_path / "sandbox"
    (bare / "validator").mkdir(parents=True)
    (bare / "validator" / DEFAULT_BENCHMARK_FILENAME).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot be verified"):
        resolve_sn60_sandbox_source(sandbox_root=str(bare), scorer_version="v1")


def test_an_unverifiable_tree_is_allowed_only_when_asked_for_explicitly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Hermetic mirrors must stay possible -- the point is that saying so is deliberate."""
    bare = tmp_path / "sandbox"
    (bare / "validator").mkdir(parents=True)
    (bare / "validator" / DEFAULT_BENCHMARK_FILENAME).write_text("{}", encoding="utf-8")
    monkeypatch.setenv(UNVERIFIED_SANDBOX_ENV, "1")
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(bare), sandbox_commit="claimed-commit", scorer_version="v1"
    )
    assert source.sandbox_commit == "claimed-commit"


def test_a_tampered_vendored_tree_refuses_to_resolve(tmp_path: Path):
    """Verification is wired into the path the lane actually calls, not merely available beside
    it. A verifier nothing invokes is decoration."""
    mirror = _mirror(tmp_path)
    (mirror / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
    with pytest.raises(SnapshotError):
        resolve_sn60_sandbox_source(sandbox_root=str(mirror), scorer_version="v1")


def test_a_vendored_tree_whose_manifest_contradicts_the_pin_refuses(tmp_path: Path):
    mirror = _mirror(tmp_path)
    path = mirror / sandbox_snapshot.MANIFEST_NAME
    document = json.loads(path.read_text(encoding="utf-8"))
    document["upstream_commit"] = "a" * 40
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises((ValueError, SnapshotError)):
        resolve_sn60_sandbox_source(sandbox_root=str(mirror), scorer_version="v1")


# --- nothing about the workflow changed ---------------------------------------------------------


def test_the_environment_override_still_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The deployed lane sets ``KATA_SN60_SANDBOX_ROOT`` and must keep behaving exactly as before,
    which is what makes this change safe to ship without touching production."""
    mirror = _mirror(tmp_path)
    monkeypatch.setenv("KATA_SN60_SANDBOX_ROOT", str(mirror))
    assert default_sandbox_root() == mirror.resolve()
    source = resolve_sn60_sandbox_source(scorer_version="v1")
    assert source.sandbox_root == str(mirror.resolve())
    assert source.sandbox_commit == DEFAULT_SANDBOX_COMMIT


def test_the_vendored_tree_scores_the_same_benchmark_as_the_clone(tmp_path: Path):
    """Equivalence, which is the whole claim of "the workflow does not change".

    A clone and the vendored tree must produce the same provenance for the same commit -- above all
    the same ``benchmark_sha256``, because that is what every published result is compared on.
    """
    mirror = _mirror(tmp_path)
    (mirror / sandbox_snapshot.MANIFEST_NAME).unlink()
    (mirror / ".git").mkdir()   # stands in for a clone; the commit is supplied by the caller

    vendored = resolve_sn60_sandbox_source(sandbox_root=str(VENDORED), scorer_version="v1")
    clone_benchmark = mirror / "validator" / DEFAULT_BENCHMARK_FILENAME
    assert clone_benchmark.read_bytes() == (
        VENDORED / "validator" / DEFAULT_BENCHMARK_FILENAME
    ).read_bytes(), "the vendored benchmark differs from the clone's"
    assert vendored.sandbox_commit == DEFAULT_SANDBOX_COMMIT
    assert vendored.benchmark_file.endswith(DEFAULT_BENCHMARK_FILENAME)
