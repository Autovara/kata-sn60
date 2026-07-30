from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest
from kata.core.tree_snapshot import SnapshotError

from kata_sn60.execution.errors import Sn60ExecutionInfrastructureError
from kata_sn60.sn60_bitsec import (
    DEFAULT_SANDBOX_COMMIT,
    Sn60ReplicaContext,
    Sn60ReplicaResult,
    build_bitsec_execution_command,
    build_default_evaluation_hook,
    build_default_execution_hook,
    ensure_internal_agent_network,
    extract_evaluation_metrics,
    extract_sn60_evaluation_payload,
    load_sn60_benchmark_project_keys,
    project_passes,
    resolve_sn60_inference_api,
    resolve_sn60_proxy_network,
    resolve_sn60_room_policy,
    resolve_sn60_room_url,
    resolve_sn60_sandbox_source,
    sn60_container_name,
    sn60_synthetic_ids,
    summarize_project,
    summarize_variant,
    validate_sn60_project_keys,
)
from kata_sn60.validator_system.challenge import sn60_variant_rank


class _FakeScorerRuntime:
    """Unit-test seam: runtime mechanics have their own tests; scorer-hook tests inspect wiring."""

    def __init__(self, root: Path) -> None:
        self.root = root / "fake-scorer-workspaces"

    @contextmanager
    def workspace(self, label: str):
        path = self.root / label
        path.mkdir(parents=True)
        for name in ("home", "tmp", "cache"):
            (path / name).mkdir()
        try:
            yield path
        finally:
            shutil.rmtree(path)

    @staticmethod
    def prepare() -> Path:
        return Path("/prepared/scorer/python")

    @staticmethod
    def environment(
        *, workspace: Path, interpreter: Path, base: dict, overrides: dict
    ) -> dict:
        return {
            **base,
            **overrides,
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(workspace / "home"),
            "TMPDIR": str(workspace / "tmp"),
        }


def _evaluation_hook(source, tmp_path: Path, *, judge_gateway=None):
    return build_default_evaluation_hook(
        source,
        judge_gateway=judge_gateway,
        scorer_runtime=_FakeScorerRuntime(tmp_path),
    )


def write_sandbox_source(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps(
            [
                {
                    "project_id": "project-alpha",
                    "vulnerabilities": [{"title": "expected alpha"}],
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def test_load_sn60_benchmark_project_keys_reads_real_snapshot_ids(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    payload = json.loads(benchmark_path.read_text(encoding="utf-8"))
    payload.extend(
        [
            {"project_id": "project-beta", "vulnerabilities": []},
            {"project_id": "project-alpha", "vulnerabilities": []},
        ]
    )
    benchmark_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )

    assert load_sn60_benchmark_project_keys(source) == ["project-alpha", "project-beta"]


def test_build_bitsec_execution_command_mounts_bundle_and_sets_pythonpath(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = Sn60ReplicaContext(
        run_id="run-1",
        variant_name="candidate",
        project_key="project-alpha",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-alpha"),
        report_path=str(tmp_path / "reports" / "project-alpha" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-alpha" / "evaluation.json"),
        sandbox_source=source,
    )

    command = build_bitsec_execution_command(context)

    assert command[:3] == ["docker", "run", "--rm"]
    assert "--name" in command
    assert sn60_container_name(context) in command
    assert "AGENT_FILE=/kata_bundle/agent.py" in command
    assert "PYTHONPATH=/kata_bundle" in command
    assert "INFERENCE_API_KEY" in command
    assert f"PROJECT_KEY={context.project_key}" in command
    assert command[-1] == "ghcr.io/bitsec-ai/project-alpha:latest"
    # Resource envelope matches the SN60 executor.
    assert "--memory" in command and "512m" in command
    assert "--cpus" in command and "0.25" in command
    assert "--pids-limit" in command and "64" in command
    # Execution carries the synthetic numeric identity, not the duel string,
    # so proxy metering is keyed per replica exactly like SN60.
    ids = sn60_synthetic_ids(context)
    assert f"JOB_RUN_ID={ids.job_run_id}" in command
    assert f"AGENT_ID={ids.agent_id}" in command
    assert f"JOB_RUN_ID={context.run_id}" not in command


def _make_context(tmp_path: Path, source, **overrides) -> Sn60ReplicaContext:
    base = dict(
        run_id="run-1",
        variant_name="candidate",
        project_key="project-alpha",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-alpha"),
        report_path=str(tmp_path / "reports" / "project-alpha" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-alpha" / "evaluation.json"),
        sandbox_source=source,
    )
    base.update(overrides)
    return Sn60ReplicaContext(**base)


def test_build_bitsec_evaluation_command_uses_synthetic_ids_and_eval_max_vulns(
    tmp_path: Path,
) -> None:
    from kata_sn60.sn60_bitsec import (
        build_bitsec_evaluation_command,
        build_bitsec_evaluation_script,
    )

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source, eval_max_vulns=25)
    ids = sn60_synthetic_ids(context)

    script = build_bitsec_evaluation_script(context)

    assert f"id={ids.job_run_id}" in script
    assert f"agent_id={ids.agent_id}" in script
    assert f"validator_id={ids.validator_id}" in script
    # eval_max_vulns is threaded from the context, not hardcoded.
    assert "eval_max_vulns=25" in script
    # The old fixed-identity form must be gone.
    assert "MockJobRun(id=1," not in script
    assert build_bitsec_evaluation_command(
        context,
        python_executable="/runtime/env/bin/python",
    ) == ["/runtime/env/bin/python", "-c", script]
    import ast

    ast.parse(script)


def test_sn60_synthetic_ids_are_distinct_and_stable(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    king_r1 = sn60_synthetic_ids(_make_context(tmp_path, source, variant_name="king"))
    king_r2 = sn60_synthetic_ids(
        _make_context(tmp_path, source, variant_name="king", replica_index=2)
    )
    cand_r1 = sn60_synthetic_ids(_make_context(tmp_path, source, variant_name="candidate"))

    # Stable for identical context.
    assert king_r1 == sn60_synthetic_ids(_make_context(tmp_path, source, variant_name="king"))
    # Distinct job_run_id per replica; distinct agent_id per side.
    assert king_r1.job_run_id != king_r2.job_run_id
    assert king_r1.agent_id == king_r2.agent_id
    assert king_r1.agent_id != cand_r1.agent_id
    assert king_r1.job_run_id != cand_r1.job_run_id
    # King and candidate share the duel-level job_id.
    assert king_r1.job_id == cand_r1.job_id
    assert all(1 <= value < 2**31 for value in (*king_r1, *cand_r1))


def test_resolve_sn60_sandbox_source_rejects_mismatched_benchmark_filename(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    write_sandbox_source(sandbox_root)
    renamed = sandbox_root / "validator" / "custom-benchmark.json"
    (sandbox_root / "validator" / "curated-highs-only-2025-08-08.json").rename(renamed)

    with pytest.raises(ValueError, match="must be named"):
        resolve_sn60_sandbox_source(
            sandbox_root=str(sandbox_root),
            benchmark_file=str(renamed),
            sandbox_commit="commit-1",
            scorer_version="ScaBenchScorerV2",
        )


def test_resolve_sn60_sandbox_source_uses_the_production_default_commit(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    monkeypatch.delenv("KATA_SN60_SANDBOX_COMMIT", raising=False)

    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit=None,
        scorer_version="ScaBenchScorerV2",
    )

    assert source.sandbox_commit == DEFAULT_SANDBOX_COMMIT


def test_default_evaluation_hook_points_validator_dir_at_recorded_benchmark(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["command"] = cmd
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    # A report WITH a finding exercises the scorer subprocess (empty reports skip it).
    _evaluation_hook(source, tmp_path)(
        context, {"success": True, "report": {"vulnerabilities": [{"title": "x"}]}}
    )

    assert captured["env"]["VALIDATOR_DIR"] == str(benchmark_path.parent)
    # The scorer joins VALIDATOR_DIR + the hardcoded filename, so that must be
    # the exact file whose hash Kata recorded.
    assert (
        Path(captured["env"]["VALIDATOR_DIR"]) / "curated-highs-only-2025-08-08.json"
    ) == benchmark_path
    assert captured["command"][0] == "/prepared/scorer/python"
    assert "uv" not in captured["command"]
    assert Path(captured["cwd"]) != sandbox_root
    assert captured["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    assert not (sandbox_root / ".venv").exists()
    assert not list(sandbox_root.rglob("__pycache__"))


def test_default_evaluation_hook_skips_scorer_on_empty_findings(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    called = {"scorer": False}

    def fake_run(cmd, *args, **kwargs):
        called["scorer"] = True
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    payload = _evaluation_hook(source, tmp_path)(
        context, {"success": True, "report": {"vulnerabilities": []}}
    )

    # The LLM judge is NOT invoked for an empty report, but the result is a valid
    # zero-true-positive success that still carries the benchmark's expected count.
    assert called["scorer"] is False
    assert payload["status"] == "success"
    assert payload["result"]["true_positives"] == 0
    assert payload["result"]["total_found"] == 0
    assert payload["result"]["total_expected"] >= 0


def test_default_evaluation_hook_ignores_agent_writable_evaluation_json(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    evaluation_path = Path(context.evaluation_path)
    evaluation_path.parent.mkdir(parents=True, exist_ok=True)
    evaluation_path.write_text(
        json.dumps(
            {
                "status": "success",
                "result": {
                    "detection_rate": 1.0,
                    "true_positives": 999,
                    "total_expected": 1,
                    "result": "PASS",
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, *a, **k: subprocess.CompletedProcess(
            cmd, 1, stdout="not json", stderr="scorer failed"
        ),
    )

    payload = _evaluation_hook(source, tmp_path)(
        context, {"success": True, "report": {"vulnerabilities": [{"title": "x"}]}}
    )

    assert payload["status"] == "error"
    assert "scorer failed" in payload["error"]
    assert payload["result"] == {}


def test_default_evaluation_hook_rejects_infrastructure_execution_failure(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    called = {"scorer": False}

    def fake_run(cmd, *args, **kwargs):
        called["scorer"] = True
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    payload = _evaluation_hook(source, tmp_path)(
        context,
        {
            "success": False,
            "infrastructure_error": True,
            "error": "Docker image ghcr.io/bitsec-ai/proj:latest is unavailable.",
        },
    )

    assert called["scorer"] is False
    assert payload["status"] == "error"
    assert "Docker image" in payload["error"]
    assert payload["result"] == {}


def _run_default_execution_hook_with_report(tmp_path, monkeypatch, source, report_text):
    """Drive the default execution hook with the docker/subprocess edges mocked,
    after the (untrusted) agent wrote `report_text` to report.json."""
    from kata_sn60 import sn60_bitsec as sn60

    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(context.report_path).write_text(report_text, encoding="utf-8")

    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")
    monkeypatch.setattr(sn60, "ensure_internal_agent_network", lambda *_a, **_k: None)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
    )
    return sn60.build_default_execution_hook(source, use_tee=False)(context)


def test_default_execution_hook_raises_on_docker_infrastructure_failure(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60 import sn60_bitsec as sn60

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)

    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")
    monkeypatch.setattr(sn60, "ensure_internal_agent_network", lambda *_a, **_k: None)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, *a, **k: subprocess.CompletedProcess(
            cmd,
            125,
            stdout="",
            stderr=(
                "Unable to find image 'ghcr.io/bitsec-ai/proj:latest' locally\n"
                "docker: Error response from daemon: pull access denied"
            ),
        ),
    )

    with pytest.raises(Sn60ExecutionInfrastructureError, match="exit code 125"):
        sn60.build_default_execution_hook(source, use_tee=False)(context)


def test_tee_execution_hook_raises_when_no_attested_result_exists(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60 import sn60_bitsec as sn60
    from kata_sn60.execution import tee_room

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    bundle = Path(context.bundle_root)
    bundle.mkdir()
    (bundle / "agent.py").write_text("def agent_main(): return {}\n", encoding="utf-8")
    monkeypatch.setenv("KATA_SN60_ROOM_URL", "https://room.example")
    monkeypatch.setenv("KATA_SN60_ROOM_MEASUREMENTS", "ab" * 32)
    monkeypatch.setattr(
        tee_room,
        "evaluate_candidate_in_room",
        lambda **_kwargs: tee_room.CandidateOutcome(
            accepted=False,
            report=None,
            reason="room run failed: room HTTP 500: container rootfs is marked read-only",
        ),
    )

    with pytest.raises(
        Sn60ExecutionInfrastructureError,
        match="container rootfs is marked read-only",
    ):
        sn60.build_tee_room_execution_hook(source)(context)


def test_attested_credential_failure_scores_zero_without_calling_the_judge(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60 import sn60_bitsec as sn60
    from kata_sn60.execution import tee_room

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-credential-zero",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    bundle = Path(context.bundle_root)
    bundle.mkdir()
    (bundle / "agent.py").write_text("def agent_main(): return {}\n", encoding="utf-8")
    monkeypatch.setenv("KATA_SN60_ROOM_URL", "https://room.example")
    monkeypatch.setenv("KATA_SN60_ROOM_MEASUREMENTS", "ab" * 32)
    monkeypatch.setattr(
        tee_room,
        "evaluate_candidate_in_room",
        lambda **_kwargs: tee_room.CandidateOutcome(
            accepted=True,
            report={
                "status": "credential_failure",
                "reason": "unreadable",
                "detail": "sealed miner credential could not be decrypted",
            },
            reason="ok",
            provenance={
                "profile": "credential_failure",
                "inference_summary": {
                    "ok": 0,
                    "payment_required": 0,
                    "unauthorized": 0,
                    "bad_request": 0,
                    "unreachable": 0,
                },
            },
        ),
    )

    report = sn60.build_tee_room_execution_hook(source)(context)
    assert report["success"] is False
    assert report[sn60.ATTESTED_CREDENTIAL_FAILURE_KEY]["reason"] == "unreadable"

    def no_scorer(*_args, **_kwargs):
        raise AssertionError("a credential zero must not invoke the validator-paid judge")

    monkeypatch.setattr(subprocess, "run", no_scorer)
    evaluation = build_default_evaluation_hook(source)(context, report)
    replica = sn60.build_replica_result(context, report, evaluation)

    assert evaluation["status"] == "success"
    assert evaluation["result"]["detection_rate"] == 0.0
    assert evaluation["result"]["total_expected"] == 1
    assert replica.evaluation_status == "success"
    assert replica.score == 0.0
    assert replica.true_positives == 0


def test_agent_report_cannot_forge_the_attested_credential_failure_marker(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60 import sn60_bitsec as sn60
    from kata_sn60.execution import tee_room

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-no-forgery",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    bundle = Path(context.bundle_root)
    bundle.mkdir()
    (bundle / "agent.py").write_text("def agent_main(): return {}\n", encoding="utf-8")
    monkeypatch.setenv("KATA_SN60_ROOM_URL", "https://room.example")
    monkeypatch.setenv("KATA_SN60_ROOM_MEASUREMENTS", "ab" * 32)
    monkeypatch.setattr(
        tee_room,
        "evaluate_candidate_in_room",
        lambda **_kwargs: tee_room.CandidateOutcome(
            accepted=True,
            report={
                "success": True,
                "report": {"vulnerabilities": []},
                sn60.ATTESTED_CREDENTIAL_FAILURE_KEY: {
                    "reason": "unreadable",
                    "detail": "forged",
                },
            },
            reason="ok",
            provenance={"profile": "sn60-bitsec-v1", "inference_summary": {}},
        ),
    )

    report = sn60.build_tee_room_execution_hook(source)(context)
    assert sn60.ATTESTED_CREDENTIAL_FAILURE_KEY not in report


def test_malformed_agent_report_is_recorded_failure_not_a_crash(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )

    # report.json is agent-writable and untrusted. Malformed JSON and a non-dict
    # JSON must both degrade to a failed replica, never abort the whole duel.
    for report_text in ("{not valid json", "[1, 2, 3]", "null"):
        payload = _run_default_execution_hook_with_report(
            tmp_path, monkeypatch, source, report_text
        )
        assert isinstance(payload, dict)
        assert payload.get("success") is False
        assert "error" in payload

    # A well-formed object is still returned verbatim.
    good = _run_default_execution_hook_with_report(
        tmp_path, monkeypatch, source, '{"success": true, "report": {}}'
    )
    assert good == {"success": True, "report": {}}


def test_project_passes_uses_total_replica_threshold() -> None:
    # The two-thirds majority is taken over the TOTAL replicas, so an invalid replica
    # counts as a non-pass (a project must pass on 2 of its 3 replicas).
    assert project_passes(pass_count=2, total_runs=3)  # PASS/PASS/FAIL or PASS/PASS/invalid
    assert project_passes(pass_count=3, total_runs=3)
    assert not project_passes(pass_count=1, total_runs=3)  # PASS/invalid/invalid -> fail
    assert not project_passes(pass_count=0, total_runs=3)
    assert not project_passes(pass_count=1, total_runs=2)
    assert not project_passes(pass_count=0, total_runs=0)


def test_resolve_sn60_sandbox_source_rejects_mismatched_pinned_commit(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    subprocess.run(["git", "init", "--quiet", str(sandbox_root)], check=True)
    subprocess.run(["git", "-C", str(sandbox_root), "add", "-A"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(sandbox_root),
            "-c",
            "user.name=kata-test",
            "-c",
            "user.email=kata-test@example.com",
            "commit",
            "--quiet",
            "-m",
            "seed",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(sandbox_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit=head,
        scorer_version="ScaBenchScorerV2",
    )
    assert source.sandbox_commit == head

    with pytest.raises(SnapshotError, match=r"HEAD is .*, expected 0{40}"):
        resolve_sn60_sandbox_source(
            sandbox_root=str(sandbox_root),
            benchmark_file=str(benchmark_path),
            sandbox_commit="0" * 40,
            scorer_version="ScaBenchScorerV2",
        )


def test_extract_evaluation_metrics_gates_all_metrics_on_success() -> None:
    metrics = extract_evaluation_metrics(
        {
            "status": "error",
            "result": {
                "detection_rate": 1.0,
                "true_positives": 8,
                "total_expected": 8,
                "total_found": 8,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "error"
    assert metrics["score"] == 0.0
    assert metrics["detection_rate"] == 0.0
    # A failed evaluation must not contribute a PASS or true positives; the
    # king variant is never invalid-gated, so ungated metrics would inflate
    # the promotion bar.
    assert metrics["result"] is None
    assert metrics["true_positives"] == 0
    assert metrics["total_expected"] == 0
    assert metrics["total_found"] == 0


def test_extract_evaluation_metrics_keeps_metrics_for_success() -> None:
    metrics = extract_evaluation_metrics(
        {
            "status": "success",
            "result": {
                "detection_rate": 0.75,
                "true_positives": 6,
                "total_expected": 8,
                "total_found": 7,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "success"
    assert metrics["score"] == 0.75
    assert metrics["result"] == "PASS"
    assert metrics["true_positives"] == 6
    assert metrics["total_expected"] == 8
    assert metrics["total_found"] == 7


def test_extract_evaluation_metrics_accepts_enum_repr_status() -> None:
    # The SN60 sandbox serializes its Status enum as "Status.SUCCESS" (via
    # json.dumps(default=str)); a valid run must not be counted as invalid.
    metrics = extract_evaluation_metrics(
        {
            "status": "Status.SUCCESS",
            "result": {
                "detection_rate": 0.5,
                "true_positives": 1,
                "total_expected": 2,
                "total_found": 1,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "success"
    assert metrics["score"] == 0.5
    assert metrics["true_positives"] == 1

    # A non-success enum status is still treated as invalid.
    failed = extract_evaluation_metrics({"status": "Status.ERROR", "result": {}})
    assert failed["evaluation_status"] == "error"
    assert failed["score"] == 0.0


def test_extract_evaluation_metrics_tolerates_malformed_numbers() -> None:
    metrics = extract_evaluation_metrics(
        {
            "status": "success",
            "result": {
                "detection_rate": "not-a-number",
                "true_positives": "NaN",
                "total_expected": None,
                "total_found": {},
                "precision": "x",
                "f1_score": [],
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "success"
    assert metrics["score"] == 0.0
    assert metrics["true_positives"] == 0
    assert metrics["total_expected"] == 0
    assert metrics["total_found"] == 0
    assert metrics["precision"] == 0.0
    assert metrics["f1_score"] == 0.0


def test_execution_subprocess_env_strips_validator_scoring_secrets(
    monkeypatch,
) -> None:
    from kata_sn60.sn60_bitsec import execution_subprocess_env

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setenv("KATA_VALIDATOR_API_KEY", "validator-key")
    monkeypatch.setenv("INFERENCE_API_KEY", "miner-key")

    env = execution_subprocess_env()

    assert "CHUTES_API_KEY" not in env
    assert "KATA_VALIDATOR_API_KEY" not in env
    assert env["INFERENCE_API_KEY"] == "miner-key"


def test_build_bitsec_evaluation_command_quotes_interpolated_values(
    tmp_path: Path,
) -> None:
    from kata_sn60.sn60_bitsec import build_bitsec_evaluation_script

    context = Sn60ReplicaContext(
        run_id="run-1",
        variant_name="candidate",
        project_key="project'; import os; os.system('x'); '",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-a"),
        report_path=str(tmp_path / "reports" / "project-a" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-a" / "evaluation.json"),
        sandbox_source=None,
    )

    script = build_bitsec_evaluation_script(context)
    # The hostile project key must survive as a single quoted literal instead
    # of terminating the string and injecting statements.
    assert repr(context.project_key) in script
    import ast

    ast.parse(script)


def _completed(cmd, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)


def test_resolve_sn60_inference_api_defaults_and_overrides(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_INFERENCE_API", raising=False)
    assert resolve_sn60_inference_api() == "http://bitsec_proxy:8000"
    monkeypatch.setenv("KATA_SN60_INFERENCE_API", " http://secret-proxy:9000 ")
    assert resolve_sn60_inference_api() == "http://secret-proxy:9000"


def test_resolve_sn60_proxy_network_defaults_and_overrides(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_PROXY_NETWORK", raising=False)
    assert resolve_sn60_proxy_network() == "bitsec-net"
    monkeypatch.setenv("KATA_SN60_PROXY_NETWORK", "kata-secret-net")
    assert resolve_sn60_proxy_network() == "kata-secret-net"


def test_sn60_room_configuration_is_strict_and_canonical(monkeypatch) -> None:
    measurement = "ab" * 32
    monkeypatch.setenv("KATA_SN60_ROOM_URL", "https://room.example/")
    monkeypatch.setenv("KATA_SN60_ROOM_MEASUREMENTS", measurement)

    assert resolve_sn60_room_url() == "https://room.example"
    assert resolve_sn60_room_policy().approved_measurements == frozenset({measurement})


@pytest.mark.parametrize(
    "url",
    [
        "room.example",
        "ftp://room.example",
        "https://user:password@room.example",
        "https://:password@room.example",
        "https://room.example?redirect=https://evil.example",
        "https://room.example#fragment",
        "http://room.example",
    ],
)
def test_sn60_room_url_rejects_unsafe_values(monkeypatch, url: str) -> None:
    monkeypatch.setenv("KATA_SN60_ROOM_URL", url)
    monkeypatch.delenv("KATA_SN60_ALLOW_INSECURE_ROOM_URL", raising=False)
    with pytest.raises(RuntimeError, match="KATA_SN60_ROOM_URL"):
        resolve_sn60_room_url()


@pytest.mark.parametrize("measurement", ["abc", "AB" * 32, "gg" * 32])
def test_sn60_room_policy_rejects_malformed_measurements(
    monkeypatch, measurement: str
) -> None:
    monkeypatch.setenv("KATA_SN60_ROOM_MEASUREMENTS", measurement)
    with pytest.raises(RuntimeError, match="64 lowercase hexadecimal"):
        resolve_sn60_room_policy()


def test_build_bitsec_execution_command_uses_configured_endpoint(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)

    command = build_bitsec_execution_command(
        context,
        proxy_network="kata-secret-net",
        inference_api="http://secret-proxy:9000",
    )

    assert "--network" in command
    assert "kata-secret-net" in command
    assert "INFERENCE_API=http://secret-proxy:9000" in command


def test_ensure_internal_agent_network_creates_when_absent() -> None:
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, returncode=1, stderr="Error: No such network: bitsec-net")
        return _completed(cmd, returncode=0)

    ensure_internal_agent_network("bitsec-net", run=fake_run)

    assert ["docker", "network", "create", "--internal", "bitsec-net"] in calls


def test_ensure_internal_agent_network_accepts_existing_internal() -> None:
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return _completed(cmd, returncode=0, stdout="true\n")

    ensure_internal_agent_network("bitsec-net", run=fake_run)

    # Existing internal network: assert only, never create.
    assert not any(cmd[:3] == ["docker", "network", "create"] for cmd in calls)


def test_ensure_internal_agent_network_rejects_non_internal() -> None:
    def fake_run(cmd, *args, **kwargs):
        return _completed(cmd, returncode=0, stdout="false\n")

    with pytest.raises(ValueError, match="permits external egress"):
        ensure_internal_agent_network("bitsec-net", run=fake_run)


def test_ensure_internal_agent_network_surfaces_inspect_errors() -> None:
    def fake_run(cmd, *args, **kwargs):
        return _completed(cmd, returncode=1, stderr="Cannot connect to the Docker daemon")

    with pytest.raises(RuntimeError, match="Failed to inspect docker network"):
        ensure_internal_agent_network("bitsec-net", run=fake_run)


def test_default_execution_hook_asserts_internal_network_and_uses_endpoint(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(context.report_path).write_text(
        json.dumps({"success": True, "report": {"vulnerabilities": []}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")
    monkeypatch.setenv("KATA_SN60_INFERENCE_API", "http://secret-proxy:9000")
    monkeypatch.delenv("KATA_SN60_PROXY_NETWORK", raising=False)

    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, returncode=0, stdout="true\n")
        return _completed(cmd, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = build_default_execution_hook(source, use_tee=False)(context)

    assert result == {"success": True, "report": {"vulnerabilities": []}}
    # The internal-network guarantee runs before the agent container starts.
    assert any(cmd[:3] == ["docker", "network", "inspect"] for cmd in calls)
    docker_run = next(cmd for cmd in calls if cmd[:2] == ["docker", "run"])
    # INFERENCE_API carries the per-problem budget token: <base>/j/<token>
    inference_env = next(a for a in docker_run if a.startswith("INFERENCE_API="))
    assert inference_env.startswith("INFERENCE_API=http://secret-proxy:9000/j/")


def test_default_execution_hook_refuses_non_internal_network(tmp_path: Path, monkeypatch) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")

    docker_ran = {"value": False}

    def fake_run(cmd, *args, **kwargs):
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, returncode=0, stdout="false\n")
        if cmd[:2] == ["docker", "run"]:
            docker_ran["value"] = True
        return _completed(cmd, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="permits external egress"):
        build_default_execution_hook(source, use_tee=False)(context)

    # Untrusted agent must never start on an egress-capable network.
    assert docker_ran["value"] is False


def test_default_execution_hook_removes_named_container_on_timeout(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")
    monkeypatch.setenv("KATA_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS", "3")

    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append((cmd, kwargs))
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, returncode=0, stdout="true\n")
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout"))
        if cmd[:3] == ["docker", "rm", "-f"]:
            return _completed(cmd, returncode=0)
        return _completed(cmd, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = build_default_execution_hook(
        source,
        use_tee=False,
        timeout_env_name="KATA_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS",
        timeout_default=300,
    )(context)

    assert result["success"] is False
    assert "timed out after 3.0 seconds" in str(result["error"])
    docker_run = next(cmd for cmd, _kwargs in calls if cmd[:2] == ["docker", "run"])
    cleanup = next(cmd for cmd, _kwargs in calls if cmd[:3] == ["docker", "rm", "-f"])
    assert sn60_container_name(context) in docker_run
    assert cleanup[-1] == sn60_container_name(context)


# --- full-grid duel execution -----------------------------------------------


def _replica(project_key: str, result: str | None, status: str = "success") -> Sn60ReplicaResult:
    return Sn60ReplicaResult(
        project_key=project_key,
        replica_index=1,
        report_path="",
        evaluation_path="",
        execution_success=True,
        evaluation_status=status,
        score=0.0,
        detection_rate=0.0,
        result=result,
        true_positives=0,
        total_expected=0,
        total_found=0,
        precision=0.0,
        f1_score=0.0,
    )


def test_summarize_variant_loose_pass_count_counts_any_replica_pass() -> None:
    # Project p passes on only 1 of 3 replicas (below the 2/3 gate); project q on none.
    results = [
        _replica("p", "PASS"),
        _replica("p", "FAIL"),
        _replica("p", "FAIL"),
        _replica("q", "FAIL"),
        _replica("q", "FAIL"),
        _replica("q", "FAIL"),
    ]
    summary = summarize_variant(
        variant_name="king",
        artifact_root=Path("/tmp/king"),
        artifact_hash="h",
        replica_results=results,
    )
    # Strict 2/3 gate: neither project passes. Loose: p counts (1 replica passed).
    assert summary.codebase_pass_count == 0
    assert summary.loose_pass_count == 1


def _scored_replica(
    project_key: str,
    *,
    true_positives: int,
    total_expected: int,
    total_found: int,
    result: str | None = None,
    status: str = "success",
) -> Sn60ReplicaResult:
    detection_rate = true_positives / total_expected if total_expected else 0.0
    precision = true_positives / total_found if total_found else 0.0
    return Sn60ReplicaResult(
        project_key=project_key,
        replica_index=1,
        report_path="",
        evaluation_path="",
        execution_success=status == "success",
        evaluation_status=status,
        score=detection_rate,
        detection_rate=detection_rate,
        result=result,
        true_positives=true_positives,
        total_expected=total_expected,
        total_found=total_found,
        precision=precision,
        f1_score=0.0,
    )


def test_summarize_project_uses_best_of_successful_replicas() -> None:
    # Two successful replicas (best finds 7 TP) plus one invalid replica. The
    # project score is that of the best successful replica -- the invalid replica
    # neither lowers true_positives nor inflates the expected denominator.
    project = summarize_project(
        project_key="p",
        replica_results=[
            _scored_replica("p", true_positives=5, total_expected=10, total_found=8),
            _scored_replica("p", true_positives=7, total_expected=10, total_found=9),
            _scored_replica("p", true_positives=0, total_expected=10, total_found=0,
                            status="error"),
        ],
    )
    assert project.true_positives == 7  # best-of, not the 12 a pooled sum would give
    assert project.total_expected == 10  # one benchmark count, not 30
    assert project.total_found == 9
    assert project.successful_runs == 2
    assert project.invalid_runs == 1


def test_project_pass_needs_two_of_three_total_replicas() -> None:
    # One PASS + two invalid replicas: 1 of 3 total is below the 2/3 gate, so the
    # project does NOT pass (invalid replicas count as non-passes). Its best-of score
    # still comes from the successful replica -- invalid runs lower the pass, not the score.
    project = summarize_project(
        project_key="p",
        replica_results=[
            _scored_replica("p", true_positives=10, total_expected=10, total_found=10,
                            result="PASS"),
            _scored_replica("p", true_positives=0, total_expected=10, total_found=0,
                            status="error"),
            _scored_replica("p", true_positives=0, total_expected=10, total_found=0,
                            status="error"),
        ],
    )
    assert project.passed is False
    assert project.pass_count == 1
    assert project.successful_runs == 1
    assert project.true_positives == 10  # best-of: the successful replica's score stands

    # Two PASS + one invalid: 2 of 3 total -> passes (invalid tolerated when 2 pass).
    project2 = summarize_project(
        project_key="q",
        replica_results=[
            _scored_replica("q", true_positives=10, total_expected=10, total_found=10,
                            result="PASS"),
            _scored_replica("q", true_positives=10, total_expected=10, total_found=10,
                            result="PASS"),
            _scored_replica("q", true_positives=0, total_expected=10, total_found=0,
                            status="error"),
        ],
    )
    assert project2.passed is True


def test_flaked_candidate_still_outranks_a_weaker_king() -> None:
    # BUG-1 regression: a genuinely stronger candidate that flakes one replica must
    # still beat a fully-successful but weaker king. Under the old pooled-sum
    # aggregation the flake deflated the candidate's true_positives and flipped the
    # winner; best-of over the successful replicas keeps the candidate ahead, and
    # invalid_runs stays only the low-priority rank tiebreaker.
    def variant(name: str, per_project_tp: int, *, flake_last: bool = False):
        replicas = []
        for project_key in ("a", "b"):
            for idx in range(3):
                invalid = flake_last and project_key == "b" and idx == 2
                replicas.append(
                    _scored_replica(
                        project_key,
                        true_positives=0 if invalid else per_project_tp,
                        total_expected=10,
                        total_found=0 if invalid else per_project_tp,
                        status="error" if invalid else "success",
                    )
                )
        return summarize_variant(
            variant_name=name,
            artifact_root=Path("/tmp") / name,
            artifact_hash=name,
            replica_results=replicas,
        )

    king = variant("king", 5)  # 5 TP/project, every replica valid
    candidate = variant("candidate", 7, flake_last=True)  # stronger, but one flaked replica

    assert king.invalid_runs == 0
    assert candidate.invalid_runs == 1
    # best-of keeps the candidate at 7+7=14 TP (not deflated) vs the king's 5+5=10.
    assert candidate.true_positives == 14
    assert king.true_positives == 10
    # true_positives is rank field 3, so the candidate wins the promotion rank.
    assert sn60_variant_rank(candidate) > sn60_variant_rank(king)


def test_extract_sn60_evaluation_payload_ignores_scorer_console_noise() -> None:
    # The pinned scorer prints Rich tables + per-finding logs to stdout, then the
    # result JSON on the last line. The whole stream is not valid JSON.
    noisy = (
        "╭── Scoring Project ──╮\n"
        "Checking: some expected vulnerability...\n"
        "LLM Response: found=False, reason=The finding is a placeholder {not json}\n"
        "✗ Missed (confidence=0.00)\n"
        '{"status": "Status.SUCCESS", "result": {"true_positives": 2, "total_expected": 9}}'
    )
    payload = extract_sn60_evaluation_payload(noisy)
    assert payload is not None
    assert payload["status"] == "Status.SUCCESS"
    assert payload["result"]["true_positives"] == 2


def test_extract_sn60_evaluation_payload_handles_clean_json() -> None:
    payload = extract_sn60_evaluation_payload('{"status": "success", "result": {}}')
    assert payload == {"status": "success", "result": {}}


def test_extract_sn60_evaluation_payload_returns_none_without_result() -> None:
    assert extract_sn60_evaluation_payload("") is None
    assert extract_sn60_evaluation_payload("just some logs\nno json here") is None
    # a JSON object without a status field is not the scorer result
    assert extract_sn60_evaluation_payload('{"foo": 1}') is None


def test_validate_sn60_project_keys_rejects_keys_missing_from_benchmark(
    tmp_path: Path,
) -> None:
    """Project keys not present in the resolved benchmark are rejected up front.

    (Direct coverage for the shared validator used across the plugin, challenge,
    and scoring paths.)
    """
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    with pytest.raises(ValueError, match="not present in the resolved benchmark"):
        validate_sn60_project_keys(["project-missing"], sandbox_source=source)


# --- judge budget gateway wiring ---------------------------------------------------------------
#
# The gateway itself is tested in test_judge_gateway.py; these cover the seam -- that the scorer is
# actually pointed at it, that a refused call fails the project CLOSED rather than publishing a
# quietly degraded score, and that the challenge-wide deadline bounds the project subprocess.


def _gateway_source(tmp_path: Path):
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    return resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )


_NONEMPTY_REPORT = {"success": True, "report": {"vulnerabilities": [{"title": "x"}]}}


def test_the_scorer_is_pointed_at_the_judge_gateway_when_one_is_active(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "success"}', stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087", limits=JudgeBudgetLimits(max_calls=10)
    ) as gateway:
        payload = _evaluation_hook(source, tmp_path, judge_gateway=gateway)(
            context, _NONEMPTY_REPORT
        )
        assert captured["env"]["PROXY_URL"] == gateway.url

    assert payload["status"] == "success"


def test_without_a_gateway_the_scorer_still_talks_to_the_proxy_directly(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60.sn60_bitsec import DEFAULT_SANDBOX_PROXY_URL

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "success"}', stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    _evaluation_hook(source, tmp_path)(context, _NONEMPTY_REPORT)

    assert captured["env"]["PROXY_URL"] == DEFAULT_SANDBOX_PROXY_URL


def test_a_nonempty_report_requires_a_validator_owned_runtime(
    tmp_path: Path, monkeypatch
) -> None:
    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)

    def fake_run(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("the scorer must not start without a trusted runtime")

    monkeypatch.setattr(subprocess, "run", fake_run)
    payload = build_default_evaluation_hook(source)(context, _NONEMPTY_REPORT)

    assert payload["status"] == "error"
    assert "no validator-owned scorer runtime" in payload["error"]


def test_a_refused_judge_call_fails_the_project_instead_of_scoring_it(
    tmp_path: Path, monkeypatch
) -> None:
    """The scorer swallows a 429 per chunk and carries on, so a budget refusal would otherwise
    surface as expected findings silently marked 'missed' -- a bad-agent verdict caused by our own
    ceiling. It has to be an error."""
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    def fake_run(cmd, *args, **kwargs):
        # Stand in for the scorer walking into the closed door mid-evaluation, then returning a
        # perfectly well-formed (but incomplete) success payload.
        scope = str(sn60_synthetic_ids(context).job_run_id)
        gateway.meter.record_refusal("max_calls 11 > 10", scope=scope)
        return subprocess.CompletedProcess(
            cmd, 0, stdout='{"status": "success", "result": {"detection_rate": 0.0}}', stderr=""
        )

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087", limits=JudgeBudgetLimits(max_calls=10)
    ) as gateway:
        payload = _evaluation_hook(source, tmp_path, judge_gateway=gateway)(
            context, _NONEMPTY_REPORT
        )

    assert payload["status"] == "error"
    assert "refused 1 scoring call" in payload["error"]
    assert "max_calls 11 > 10" in payload["error"]
    assert payload["result"] == {}


@pytest.mark.parametrize("scope_header", [None, "unknown", "2147483647"])
def test_unattributed_judge_call_cannot_publish_a_degraded_score(
    tmp_path: Path, monkeypatch, scope_header: str | None
) -> None:
    """The expected bucket is validator-registered; a scorer-chosen missing/wrong bucket is
    rejected and the hook observes the global protocol failure."""
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    def fake_run(cmd, *args, **kwargs):
        headers = {"Content-Type": "application/json"}
        if scope_header is not None:
            headers["x-job-run-id"] = scope_header
        request = urllib.request.Request(
            f"{gateway.url}/inference",
            data=b'{"messages":[]}',
            headers=headers,
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)
        assert exc.value.code == 403
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "success"}', stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087", limits=JudgeBudgetLimits(max_calls=10)
    ) as gateway:
        payload = _evaluation_hook(source, tmp_path, judge_gateway=gateway)(
            context, _NONEMPTY_REPORT
        )

    assert payload["status"] == "error"
    assert "unattributed or malformed" in payload["error"]
    assert gateway.usage().protocol_errors == 1


def test_only_refusals_from_this_project_fail_this_project(tmp_path: Path, monkeypatch) -> None:
    """Refusals accumulate across the whole challenge, so the check has to be a delta -- otherwise
    one refused project would poison every project scored after it."""
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    def fake_run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "success"}', stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087", limits=JudgeBudgetLimits(max_calls=10)
    ) as gateway:
        gateway.meter.record_refusal("an earlier project's refusal", scope="different-job")
        payload = _evaluation_hook(source, tmp_path, judge_gateway=gateway)(
            context, _NONEMPTY_REPORT
        )

    assert payload["status"] == "success"


def test_an_upstream_judge_failure_fails_only_its_evaluation(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    def fake_run(cmd, *args, **kwargs):
        scope = str(sn60_synthetic_ids(context).job_run_id)
        hold = gateway.meter.reserve(request_chars=10, scope=scope)
        gateway.meter.settle_worst_case(hold)
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout='{"status": "success", "result": {"detection_rate": 0.0}}',
            stderr="",
        )

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087", limits=JudgeBudgetLimits(max_calls=10)
    ) as gateway:
        payload = _evaluation_hook(source, tmp_path, judge_gateway=gateway)(
            context, _NONEMPTY_REPORT
        )

    assert payload["status"] == "error"
    assert "upstream failure" in payload["error"]
    assert payload["result"] == {}


def test_the_challenge_deadline_bounds_the_project_subprocess_timeout(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "success"}', stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    # The per-project timeout alone is an hour, and several projects run concurrently.
    monkeypatch.setenv("KATA_SN60_EVALUATION_TIMEOUT_SECONDS", "3600")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087",
        limits=JudgeBudgetLimits(max_calls=10, challenge_deadline_seconds=90),
    ) as gateway:
        _evaluation_hook(source, tmp_path, judge_gateway=gateway)(context, _NONEMPTY_REPORT)

    assert 0 < captured["timeout"] <= 90


def test_a_project_scored_after_the_deadline_is_refused_without_spawning_the_scorer(
    tmp_path: Path, monkeypatch
) -> None:
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    def fake_run(cmd, *args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("the scorer must not run once the judge deadline has passed")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    clock = iter([0.0] + [1000.0] * 50)
    with JudgeGateway(
        upstream_url="http://upstream:8087",
        limits=JudgeBudgetLimits(max_calls=10, challenge_deadline_seconds=60),
        clock=lambda: next(clock),
    ) as gateway:
        payload = _evaluation_hook(source, tmp_path, judge_gateway=gateway)(
            context, _NONEMPTY_REPORT
        )

    assert payload["status"] == "error"
    assert "deadline elapsed" in payload["error"]


def test_a_judge_call_with_no_usage_receipt_does_not_fail_the_project(
    tmp_path: Path, monkeypatch
) -> None:
    """The score is complete when the judge answered; only the accounting is blind. Charging the
    reservation keeps the money conservative, and failing the round on top of that would discard
    good paid work over a bookkeeping gap. Contrast with the upstream-failure test below."""
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    def fake_run(cmd, *args, **kwargs):
        # Stand in for a judge call that answered without a readable receipt.
        scope = str(sn60_synthetic_ids(context).job_run_id)
        gateway.meter.settle_worst_case(
            gateway.meter.reserve(request_chars=100, scope=scope), upstream_error=False
        )
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "success"}', stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087", limits=JudgeBudgetLimits(max_calls=10)
    ) as gateway:
        payload = build_default_evaluation_hook(
            source, judge_gateway=gateway, scorer_runtime=_FakeScorerRuntime(tmp_path)
        )(context, _NONEMPTY_REPORT)
        usage = gateway.usage()

    assert payload["status"] == "success"
    assert usage.unmetered_calls == 1
    assert usage.output_tokens > 0          # still charged


def test_a_judge_upstream_failure_still_fails_the_project(tmp_path: Path, monkeypatch) -> None:
    """The separation is only safe if the genuine failure keeps failing: an unanswered call means
    findings went unchecked, which is a degraded score and must never be published."""
    from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway

    source = _gateway_source(tmp_path)
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    def fake_run(cmd, *args, **kwargs):
        scope = str(sn60_synthetic_ids(context).job_run_id)
        gateway.meter.settle_worst_case(gateway.meter.reserve(request_chars=100, scope=scope))
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "success"}', stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    with JudgeGateway(
        upstream_url="http://upstream:8087", limits=JudgeBudgetLimits(max_calls=10)
    ) as gateway:
        payload = build_default_evaluation_hook(
            source, judge_gateway=gateway, scorer_runtime=_FakeScorerRuntime(tmp_path)
        )(context, _NONEMPTY_REPORT)

    assert payload["status"] == "error"
    assert "upstream failure" in payload["error"]


# --- one unusable key must not stop the competition ----------------------------------------------


def test_a_key_the_room_cannot_decrypt_scores_zero_instead_of_aborting() -> None:
    """The live failure: the king's sealed key was sealed to an older room key, the room answered
    HTTP 400, and the WHOLE round aborted -- so one contestant's unusable key stopped the
    competition for everyone. A key that does not open is a property of that submission, so it
    scores zero for that side and the round carries on."""
    from kata_sn60.sn60_bitsec import (
        ATTESTED_CREDENTIAL_FAILURE_KEY,
        UNATTESTED_CREDENTIAL_FAILURE_REASON,
        attested_credential_failure,
        report_finding_count,
        room_undecryptable_credential,
    )

    reason = (
        'room run failed: room HTTP 400: '
        '{"error":"sealed miner credential could not be decrypted"}'
    )
    assert room_undecryptable_credential(reason) is True

    payload = {
        "success": False,
        "report": {"vulnerabilities": []},
        ATTESTED_CREDENTIAL_FAILURE_KEY: {
            "reason": UNATTESTED_CREDENTIAL_FAILURE_REASON,
            "detail": reason,
        },
    }
    failure = attested_credential_failure(payload)
    assert failure is not None
    assert failure["reason"] == UNATTESTED_CREDENTIAL_FAILURE_REASON
    # Zero, not an error: no findings, so no true positives.
    assert report_finding_count(payload) == 0


@pytest.mark.parametrize(
    "reason",
    [
        'room run failed: room HTTP 503: {"error":"upstream unavailable"}',
        "room run failed: transport error after 3 attempts",
        "room quote verification failed: unapproved measurement",
        'room run failed: room HTTP 500: '
        '{"error":"sealed miner credential could not be decrypted"}',
        "",
    ],
)
def test_a_room_side_failure_still_aborts_rather_than_zeroing_a_contestant(reason: str) -> None:
    """The boundary that makes the above safe. Zeroing on anything but a 400-with-message would
    punish a contestant for an outage they had no part in -- and a room-wide fault would then zero
    every entrant at once. Note the 500 case: same message, still an abort, because a server error
    is the room failing rather than the key being bad."""
    from kata_sn60.sn60_bitsec import room_undecryptable_credential

    assert room_undecryptable_credential(reason) is False


def test_an_unknown_credential_reason_is_not_silently_scored_as_zero() -> None:
    """The marker is validator-reserved and the reason set is closed, so a forged or unrecognised
    reason cannot turn into a free zero-score path."""
    from kata_sn60.sn60_bitsec import ATTESTED_CREDENTIAL_FAILURE_KEY, attested_credential_failure

    assert attested_credential_failure(
        {ATTESTED_CREDENTIAL_FAILURE_KEY: {"reason": "made-up", "detail": "x"}}
    ) is None
