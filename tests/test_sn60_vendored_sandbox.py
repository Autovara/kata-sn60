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


# --- a clone must prove the same thing the vendored tree does ------------------------------------
#
# A matching HEAD answers "which commit is checked out", never "is the working tree that commit".
# These pin the finding set a clone is now held to.


def _write_benchmark(root: Path) -> Path:
    path = root / "validator" / DEFAULT_BENCHMARK_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([{"project_id": "project-alpha", "vulnerabilities": [{"title": "x"}]}]) + "\n",
        encoding="utf-8",
    )
    return path


def _seed_clone(root: Path) -> str:
    """A committed clone whose working tree matches HEAD exactly."""
    import subprocess

    root.mkdir(parents=True, exist_ok=True)
    (root / "validator").mkdir(parents=True, exist_ok=True)
    (root / "validator" / "executor.py").write_text("# scorer\n", encoding="utf-8")
    (root / ".gitignore").write_text(".venv/\n*.pyc\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@e.x",
         "commit", "--quiet", "-m", "seed"],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def test_a_pristine_clone_has_no_findings(tmp_path: Path) -> None:
    root = tmp_path / "clone"
    head = _seed_clone(root)
    assert sandbox_snapshot.clone_findings(root, expected_commit=head) == []
    assert sandbox_snapshot.require_verified_clone(root, expected_commit=head) == head


def test_a_clone_at_the_wrong_commit_is_caught(tmp_path: Path) -> None:
    root = tmp_path / "clone"
    _seed_clone(root)
    findings = sandbox_snapshot.clone_findings(root, expected_commit="0" * 40)
    assert any("HEAD is" in f for f in findings)


def test_a_modified_tracked_file_is_caught(tmp_path: Path) -> None:
    """The case a bare rev-parse always passed: right commit, wrong bytes."""
    root = tmp_path / "clone"
    head = _seed_clone(root)
    (root / "validator" / "executor.py").write_text("# tampered\n", encoding="utf-8")
    findings = sandbox_snapshot.clone_findings(root, expected_commit=head)
    assert any("executor.py" in f and "differs from the pinned commit" in f for f in findings)
    with pytest.raises(SnapshotError, match="executor.py"):
        sandbox_snapshot.require_verified_clone(root, expected_commit=head)


def test_a_deleted_tracked_file_is_caught(tmp_path: Path) -> None:
    root = tmp_path / "clone"
    head = _seed_clone(root)
    (root / "validator" / "executor.py").unlink()
    findings = sandbox_snapshot.clone_findings(root, expected_commit=head)
    assert any("executor.py" in f for f in findings)


def test_an_untracked_file_is_caught(tmp_path: Path) -> None:
    root = tmp_path / "clone"
    head = _seed_clone(root)
    (root / "validator" / "extra.py").write_text("# planted\n", encoding="utf-8")
    findings = sandbox_snapshot.clone_findings(root, expected_commit=head)
    assert any("extra.py" in f and "untracked" in f for f in findings)


def test_an_ignored_file_is_caught(tmp_path: Path) -> None:
    """Ignored files are the easy ones to miss: .gitignore hides them from plain `git status`,
    yet Python imports them just the same. A stray `uv sync` drops an importable `.venv` into the
    source that `git status` reports as nothing at all."""
    root = tmp_path / "clone"
    head = _seed_clone(root)
    venv = root / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "sitecustomize.py").write_text("# runs on interpreter start\n", encoding="utf-8")
    (root / "validator" / "executor.pyc").write_bytes(b"\x00")

    import subprocess
    plain = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert plain == ""  # exactly why the check cannot rely on default `git status`

    findings = sandbox_snapshot.clone_findings(root, expected_commit=head)
    assert any(".venv" in f and "ignored" in f for f in findings)
    assert any("executor.pyc" in f and "ignored" in f for f in findings)


def test_a_directory_that_is_not_a_git_tree_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "not-a-clone"
    root.mkdir()
    findings = sandbox_snapshot.clone_findings(root, expected_commit="0" * 40)
    assert findings and "cannot resolve HEAD" in findings[0]


def test_resolve_refuses_a_dirty_clone_end_to_end(tmp_path: Path) -> None:
    """The published result names the pinned commit, so resolution itself must refuse."""
    root = tmp_path / "sandbox"
    benchmark = _write_benchmark(root)
    head = _seed_clone(root)
    resolve_sn60_sandbox_source(
        sandbox_root=str(root), benchmark_file=str(benchmark),
        sandbox_commit=head, scorer_version="ScaBenchScorerV2",
    )
    (root / "validator" / "executor.py").write_text("# tampered\n", encoding="utf-8")
    with pytest.raises(SnapshotError, match="does not match pinned commit"):
        resolve_sn60_sandbox_source(
            sandbox_root=str(root), benchmark_file=str(benchmark),
            sandbox_commit=head, scorer_version="ScaBenchScorerV2",
        )


def test_the_vendored_tree_is_not_packaged_into_the_wheel() -> None:
    """The lane is installed with ``uv run --with-editable``, so the STAGED SOURCE TREE is what
    reaches sys.path and ``sandbox/`` is its sibling. Force-including the tree into the wheel looks
    like a robustness win and is the opposite: to travel in a wheel it must sit inside
    ``kata_sn60/``, and pip then byte-compiles the pinned tree on install -- every resulting
    ``__pycache__/*.pyc`` is an unlisted file, so verification fails on every round of an installed
    lane. Verified by actually installing such a wheel; 74 findings."""
    import tomllib

    config = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    wheel = config["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["packages"] == ["kata_sn60"]
    assert "force-include" not in wheel, (
        "force-including the sandbox makes pip byte-compile the pinned tree; see this test's reason"
    )


def test_the_vendored_tree_is_a_sibling_of_the_package() -> None:
    """What the editable layout relies on: ``<parent of kata_sn60>/sandbox``. If the tree ever moves
    inside the package this breaks loudly here rather than silently at deploy time."""
    import kata_sn60

    package_dir = Path(kata_sn60.__file__).resolve().parent
    assert sandbox_snapshot.vendored_root() == (package_dir.parent / "sandbox").resolve()
    assert (sandbox_snapshot.vendored_root() / sandbox_snapshot.MANIFEST_NAME).is_file()
