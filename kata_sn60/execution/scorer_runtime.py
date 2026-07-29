"""Immutable-source runtime for the pinned SN60 scorer.

The Bitsec source tree is evidence: Kata verifies it before a challenge and must not use it as a
working directory or a virtual-environment location.  This module keeps the three different kinds
of state separate:

* ``source_root`` is verified, read-only input.
* ``runtime_root`` contains a dependency environment prepared from the pinned ``uv.lock``.
* ``workspace_root`` contains short-lived, per-evaluation working directories.

Environment preparation is serialized across processes and published by atomic rename.  Scoring
then invokes the prepared interpreter directly; no ``uv run`` or dependency synchronization occurs
on the paid path.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Mapping

SCORER_RUNTIME_ROOT_ENV = "KATA_SN60_SCORER_RUNTIME_ROOT"
SCORER_PREPARE_TIMEOUT_ENV = "KATA_SN60_SCORER_PREPARE_TIMEOUT_SECONDS"
DEFAULT_SCORER_PREPARE_TIMEOUT_SECONDS = 20 * 60
RUNTIME_SCHEMA_VERSION = 1
_STAMP_NAME = "kata-sn60-runtime.json"
_FINGERPRINT_FILES = ("pyproject.toml", "uv.lock")
LOGGER = logging.getLogger(__name__)


class ScorerRuntimeError(RuntimeError):
    """The scorer environment cannot be prepared or used safely."""


def resolve_scorer_runtime_root(challenge_root: Path) -> Path:
    """Return a durable writable root outside both the verified tree and an individual run.

    Production sets ``KATA_SN60_SCORER_RUNTIME_ROOT`` explicitly.  The derived fallback keeps local
    challenge commands usable and deliberately places the cache beside, never inside, a challenge.
    A conventional ``.../runs/<run-id>`` output resolves to ``.../sn60-scorer-runtime``.
    """

    configured = os.environ.get(SCORER_RUNTIME_ROOT_ENV, "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    root = Path(challenge_root).expanduser().resolve()
    for ancestor in (root, *root.parents):
        if ancestor.name == "runs":
            return ancestor.parent / "sn60-scorer-runtime"
    return root.parent / ".sn60-scorer-runtime"


def _positive_timeout(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ScorerRuntimeError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ScorerRuntimeError(f"{name} must be positive, got {raw!r}")
    return value


class ScorerRuntime:
    """Prepared dependencies plus isolated workspaces for one verified scorer source."""

    def __init__(
        self,
        *,
        source_root: Path,
        runtime_root: Path,
        workspace_root: Path,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self.source_root = Path(source_root).expanduser().resolve()
        self.runtime_root = Path(runtime_root).expanduser().resolve()
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self._runner = runner

    @classmethod
    def for_challenge(
        cls,
        *,
        source_root: Path,
        challenge_root: Path,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> "ScorerRuntime":
        challenge_root = Path(challenge_root).expanduser().resolve()
        return cls(
            source_root=source_root,
            runtime_root=resolve_scorer_runtime_root(challenge_root),
            workspace_root=challenge_root / ".scorer-workspaces",
            runner=runner,
        )

    def __enter__(self) -> "ScorerRuntime":
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def _fingerprint(self) -> str:
        digest = hashlib.sha256()
        digest.update(f"kata-sn60-scorer-runtime:{RUNTIME_SCHEMA_VERSION}\0".encode())
        digest.update(sys.version.encode())
        digest.update(b"\0")
        for relative in _FINGERPRINT_FILES:
            path = self.source_root / relative
            if not path.is_file() or path.is_symlink():
                raise ScorerRuntimeError(
                    f"verified SN60 scorer is missing regular file {relative}: {path}"
                )
            digest.update(relative.encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        # A vendored manifest changes whenever any verified source byte changes.  It is not needed
        # to resolve dependencies, but including it prevents a runtime prepared for one audited
        # scorer snapshot from being presented as belonging to another.
        manifest = self.source_root / "SANDBOX_MANIFEST.json"
        if manifest.is_file() and not manifest.is_symlink():
            digest.update(manifest.read_bytes())
        return digest.hexdigest()

    def _environment_dir(self) -> Path:
        return self.runtime_root / "envs" / self._fingerprint()

    @staticmethod
    def _stamp_payload(fingerprint: str) -> dict[str, object]:
        return {
            "schema_version": RUNTIME_SCHEMA_VERSION,
            "fingerprint": fingerprint,
            "python_version": sys.version,
        }

    def _is_prepared(self, environment_dir: Path, fingerprint: str) -> bool:
        python = environment_dir / "bin" / "python"
        stamp = environment_dir / _STAMP_NAME
        if not python.exists() or not stamp.is_file() or stamp.is_symlink():
            return False
        try:
            payload = json.loads(stamp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return payload == self._stamp_payload(fingerprint)

    def prepare(self) -> Path:
        """Return the external interpreter, preparing it exactly once for this lock fingerprint."""

        fingerprint = self._fingerprint()
        environment_dir = self.runtime_root / "envs" / fingerprint
        locks_dir = self.runtime_root / "locks"
        cache_dir = self.runtime_root / "uv-cache"
        home_dir = self.runtime_root / "home"
        xdg_cache_dir = self.runtime_root / "xdg-cache"
        for directory in (
            environment_dir.parent,
            locks_dir,
            cache_dir,
            home_dir,
            xdg_cache_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = locks_dir / f"{fingerprint}.lock"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        temporary: Path | None = None
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if self._is_prepared(environment_dir, fingerprint):
                return environment_dir / "bin" / "python"

            temporary = Path(
                tempfile.mkdtemp(
                    prefix=f".{fingerprint[:12]}.preparing-",
                    dir=environment_dir.parent,
                )
            )
            command = [
                "uv",
                "sync",
                "--frozen",
                "--no-dev",
                "--no-install-project",
                "--project",
                str(self.source_root),
                "--python",
                sys.executable,
            ]
            prepare_env = {
                **os.environ,
                "UV_PROJECT_ENVIRONMENT": str(temporary),
                "UV_CACHE_DIR": str(cache_dir),
                "UV_PYTHON_DOWNLOADS": "never",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "HOME": str(home_dir),
                "XDG_CACHE_HOME": str(xdg_cache_dir),
            }
            run = self._runner or subprocess.run
            try:
                completed = run(
                    command,
                    cwd=str(self.runtime_root),
                    env=prepare_env,
                    capture_output=True,
                    text=True,
                    timeout=_positive_timeout(
                        SCORER_PREPARE_TIMEOUT_ENV,
                        DEFAULT_SCORER_PREPARE_TIMEOUT_SECONDS,
                    ),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ScorerRuntimeError(
                    f"failed to prepare SN60 scorer environment: {exc}"
                ) from exc
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout or "").strip()
                raise ScorerRuntimeError(
                    "failed to prepare frozen SN60 scorer environment"
                    + (f": {detail}" if detail else "")
                )
            python = temporary / "bin" / "python"
            if not python.exists():
                raise ScorerRuntimeError(
                    f"uv reported success but created no scorer interpreter at {python}"
                )
            (temporary / _STAMP_NAME).write_text(
                json.dumps(self._stamp_payload(fingerprint), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if environment_dir.exists():
                shutil.rmtree(environment_dir)
            os.replace(temporary, environment_dir)
            temporary = None
            return environment_dir / "bin" / "python"
        finally:
            if temporary is not None:
                shutil.rmtree(temporary, ignore_errors=True)
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    @contextmanager
    def workspace(self, label: str) -> Iterator[Path]:
        """Yield one unique writable directory and remove it on every normal error path."""

        self.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        safe_label = re.sub(r"[^a-zA-Z0-9_.-]+", "-", label).strip(".-")[:60] or "evaluation"
        path = Path(
            tempfile.mkdtemp(
                prefix=f"{safe_label}-{uuid.uuid4().hex[:8]}-",
                dir=self.workspace_root,
            )
        )
        try:
            for name in ("home", "tmp", "cache"):
                (path / name).mkdir(mode=0o700)
            yield path
        finally:
            try:
                shutil.rmtree(path)
            except OSError:
                # Cleanup is hygiene, not part of the score. A transient filesystem failure after
                # a paid scorer subprocess succeeds must not turn that completed work into an
                # invalid result.
                LOGGER.warning("could not remove SN60 scorer workspace %s", path, exc_info=True)

    def environment(
        self,
        *,
        workspace: Path,
        interpreter: Path,
        base: Mapping[str, str],
        overrides: Mapping[str, str],
    ) -> dict[str, str]:
        # A virtualenv's ``bin/python`` is commonly a symlink to the base interpreter. Keep the
        # absolute venv path instead of resolving that symlink, or VIRTUAL_ENV and PATH would point
        # at the system Python prefix while the command itself still uses the venv.
        interpreter = Path(os.path.abspath(Path(interpreter).expanduser()))
        environment_dir = interpreter.parent.parent
        workspace = Path(workspace).resolve()
        inherited_path = base.get("PATH", "")
        executable_path = str(interpreter.parent)
        if inherited_path:
            executable_path = f"{executable_path}{os.pathsep}{inherited_path}"
        return {
            **base,
            **overrides,
            # Never append an empty PATH component: POSIX interprets it as the current working
            # directory, which would make the writable scorer workspace executable search input.
            "PATH": executable_path,
            "VIRTUAL_ENV": str(environment_dir),
            "PYTHONPATH": str(self.source_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "HOME": str(workspace / "home"),
            "TMPDIR": str(workspace / "tmp"),
            "XDG_CACHE_HOME": str(workspace / "cache"),
            # Defensive even though the command invokes Python directly: a dependency importing
            # uv must still never discover or synchronize the verified project.
            "UV_PROJECT_ENVIRONMENT": str(environment_dir),
        }

    def cleanup(self) -> None:
        """Remove transient workspaces while preserving the dependency environment."""

        if self.workspace_root.exists():
            try:
                shutil.rmtree(self.workspace_root)
            except OSError:
                LOGGER.warning(
                    "could not remove SN60 scorer workspace root %s",
                    self.workspace_root,
                    exc_info=True,
                )


__all__ = [
    "DEFAULT_SCORER_PREPARE_TIMEOUT_SECONDS",
    "SCORER_PREPARE_TIMEOUT_ENV",
    "SCORER_RUNTIME_ROOT_ENV",
    "ScorerRuntime",
    "ScorerRuntimeError",
    "resolve_scorer_runtime_root",
]
