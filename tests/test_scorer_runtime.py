from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from kata_sn60.execution.scorer_runtime import (
    SCORER_RUNTIME_ROOT_ENV,
    ScorerRuntime,
    ScorerRuntimeError,
    resolve_scorer_runtime_root,
)


def _source(root: Path) -> Path:
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname="scorer"\nversion="0"\nrequires-python=">=3.11"\n',
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\nrevision = 3\n", encoding="utf-8")
    (root / "validator").mkdir()
    (root / "validator" / "executor.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _successful_runner(calls: list[tuple]) -> object:
    def run(command, **kwargs):
        calls.append((command, kwargs))
        environment = Path(kwargs["env"]["UV_PROJECT_ENVIRONMENT"])
        (environment / "bin").mkdir(parents=True)
        (environment / "bin" / "python").write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    return run


def test_prepare_builds_once_outside_the_verified_source_and_never_changes_it(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path / "source")
    before = _snapshot(source)
    calls: list[tuple] = []
    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=_successful_runner(calls),
    )

    first = runtime.prepare()
    second = runtime.prepare()

    assert first == second
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:2] == ["uv", "sync"]
    assert "--locked" in command  # --frozen would accept a stale lock; see prepare()
    assert "--no-install-project" in command
    assert command[command.index("--project") + 1] == str(source)
    assert Path(kwargs["cwd"]) == tmp_path / "runtime"
    assert Path(kwargs["env"]["UV_PROJECT_ENVIRONMENT"]).is_relative_to(tmp_path / "runtime")
    assert kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"
    assert kwargs["env"]["PYTHONNOUSERSITE"] == "1"
    assert Path(kwargs["env"]["HOME"]).is_relative_to(tmp_path / "runtime")
    assert _snapshot(source) == before
    assert not (source / ".venv").exists()
    assert not list(source.rglob("__pycache__"))


def test_concurrent_prepare_publishes_one_complete_environment(tmp_path: Path) -> None:
    source = _source(tmp_path / "source")
    calls: list[tuple] = []
    calls_lock = threading.Lock()

    def runner(command, **kwargs):
        with calls_lock:
            calls.append((command, kwargs))
        time.sleep(0.05)
        environment = Path(kwargs["env"]["UV_PROJECT_ENVIRONMENT"])
        (environment / "bin").mkdir(parents=True)
        (environment / "bin" / "python").write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=runner,
    )
    results: list[Path] = []
    threads = [threading.Thread(target=lambda: results.append(runtime.prepare())) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(calls) == 1
    assert len(results) == 3
    assert len(set(results)) == 1
    assert results[0].exists()


def test_each_evaluation_gets_an_isolated_workspace_and_cleanup(tmp_path: Path) -> None:
    source = _source(tmp_path / "source")
    calls: list[tuple] = []
    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=_successful_runner(calls),
    )
    interpreter = runtime.prepare()

    with runtime.workspace("candidate/project") as first:
        with runtime.workspace("candidate/project") as second:
            assert first != second
            environment = runtime.environment(
                workspace=first,
                interpreter=interpreter,
                base={"PATH": "/usr/bin"},
                overrides={"VALIDATOR_DIR": "/verified/validator"},
            )
            assert environment["PYTHONPATH"] == str(source)
            assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
            assert environment["PYTHONNOUSERSITE"] == "1"
            assert environment["HOME"] == str(first / "home")
            assert environment["TMPDIR"] == str(first / "tmp")
            assert environment["VALIDATOR_DIR"] == "/verified/validator"
        assert not second.exists()
    assert not first.exists()
    assert len(calls) == 1


def test_environment_never_adds_the_workspace_to_an_empty_path(tmp_path: Path) -> None:
    source = _source(tmp_path / "source")
    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=_successful_runner([]),
    )
    interpreter = runtime.prepare()
    with runtime.workspace("candidate") as workspace:
        environment = runtime.environment(
            workspace=workspace,
            interpreter=interpreter,
            base={},
            overrides={},
        )

    assert environment["PATH"] == str(interpreter.parent)
    assert not environment["PATH"].endswith(":")


def test_environment_keeps_the_virtualenv_path_when_python_is_a_symlink(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path / "source")
    environment_dir = tmp_path / "runtime" / "envs" / "fingerprint"
    interpreter = environment_dir / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(Path("/usr/bin/python3"))
    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
    )
    with runtime.workspace("candidate") as workspace:
        environment = runtime.environment(
            workspace=workspace,
            interpreter=interpreter,
            base={"PATH": "/usr/bin"},
            overrides={},
        )

    assert environment["VIRTUAL_ENV"] == str(environment_dir)
    assert environment["PATH"].split(":")[0] == str(environment_dir / "bin")


def test_failed_prepare_leaves_no_publishable_partial_environment(tmp_path: Path) -> None:
    source = _source(tmp_path / "source")

    def runner(command, **kwargs):
        environment = Path(kwargs["env"]["UV_PROJECT_ENVIRONMENT"])
        (environment / "bin").mkdir(parents=True)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="lock mismatch")

    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=runner,
    )

    with pytest.raises(ScorerRuntimeError, match="lock mismatch"):
        runtime.prepare()

    assert not list((tmp_path / "runtime" / "envs").glob("[0-9a-f]" * 64))
    assert not list((tmp_path / "runtime" / "envs").glob("*.preparing-*"))


def test_runtime_root_is_explicit_in_production_and_stable_beside_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(SCORER_RUNTIME_ROOT_ENV, raising=False)
    challenge = tmp_path / "kata" / "runs" / "challenge-1"
    assert resolve_scorer_runtime_root(challenge) == tmp_path / "kata" / "sn60-scorer-runtime"

    configured = tmp_path / "configured"
    monkeypatch.setenv(SCORER_RUNTIME_ROOT_ENV, str(configured))
    assert resolve_scorer_runtime_root(challenge) == configured


def test_cleanup_never_removes_the_durable_dependency_environment(tmp_path: Path) -> None:
    source = _source(tmp_path / "source")
    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=_successful_runner([]),
    )
    interpreter = runtime.prepare()
    runtime.workspace_root.mkdir(parents=True)
    (runtime.workspace_root / "stale").mkdir()

    runtime.cleanup()

    assert not runtime.workspace_root.exists()
    assert interpreter.exists()


def test_workspace_cleanup_failure_does_not_discard_completed_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    source = _source(tmp_path / "source")
    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=_successful_runner([]),
    )
    original_rmtree = shutil.rmtree
    workspace_path: Path | None = None

    def fail_workspace(path, *args, **kwargs):
        if workspace_path is not None and Path(path) == workspace_path:
            raise OSError("busy")
        return original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", fail_workspace)
    with runtime.workspace("completed") as workspace:
        workspace_path = workspace
        (workspace / "result.json").write_text("{}", encoding="utf-8")

    assert workspace_path is not None and workspace_path.exists()
    assert "could not remove SN60 scorer workspace" in caplog.text
    original_rmtree(workspace_path)


def test_context_exit_treats_challenge_cleanup_as_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    source = _source(tmp_path / "source")
    runtime = ScorerRuntime(
        source_root=source,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "challenge" / "workspaces",
        runner=_successful_runner([]),
    )
    runtime.workspace_root.mkdir(parents=True)
    original_rmtree = shutil.rmtree

    def fail_root(path, *args, **kwargs):
        if Path(path) == runtime.workspace_root:
            raise OSError("busy")
        return original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", fail_root)
    with runtime:
        pass

    assert runtime.workspace_root.exists()
    assert "could not remove SN60 scorer workspace root" in caplog.text
    original_rmtree(runtime.workspace_root)
