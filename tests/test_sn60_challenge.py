from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60.sn60_bitsec import (
    Sn60ProjectAggregate,
    Sn60ReplicaContext,
    Sn60ReplicaResult,
    Sn60VariantSummary,
)
from kata_sn60.validator_system import (
    evaluate_sn60_promotion,
)


def _run_challenge(
    *,
    king_artifact_path,
    candidates,
    project_keys,
    output_root=None,
    replicas_per_project=1,
    sandbox_root=None,
    benchmark_file=None,
    sandbox_commit=None,
    execution_hook=None,
    evaluation_hook=None,
    progress_path=None,
    **_ignored,
):
    """Score the king + candidates through the SN60 plugin challenge (the real path)."""
    from kata_sn60 import Sn60BitsecPlugin, run_sn60_plugin_challenge

    return run_sn60_plugin_challenge(
        king_artifact_path=king_artifact_path,
        candidates=candidates,
        config={
            "sandbox_root": sandbox_root,
            "benchmark_file": benchmark_file,
            "sandbox_commit": sandbox_commit,
            "project_keys": project_keys,
            "replicas_per_project": replicas_per_project,
        },
        output_root=output_root or "runs",
        plugin=Sn60BitsecPlugin(execution_hook=execution_hook, evaluation_hook=evaluation_hook),
        progress_path=progress_path,
    )


SCREENING_DESCRIPTION = (
    "A privileged state-changing function can be called by any account, "
    "allowing unauthorized changes to protected protocol settings."
)
VALID_SCREENING_REPORT = {
    "vulnerabilities": [
        {
            "title": "Missing access control on privileged update",
            "description": SCREENING_DESCRIPTION,
            "severity": "high",
            "file": "contracts/Admin.sol",
        }
    ]
}


def write_bundle(root: Path, title: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        "def agent_main(project_dir=None, inference_api=None):\n"
        f"    finding = {{'title': '{title}'}}\n"
        "    return {'vulnerabilities': [finding]}\n",
        encoding="utf-8",
    )


def write_sandbox_source(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps(
            [
                {
                    "project_id": "project-alpha",
                    "vulnerabilities": [{"title": "expected"}],
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def test_evaluate_sn60_promotion_uses_invalid_runs_as_last_tiebreaker() -> None:
    king = build_variant(
        "king", aggregated_score=0.5, codebase_pass_count=1, true_positives=2, invalid_runs=0
    )
    candidate = build_variant(
        "candidate", aggregated_score=0.5, codebase_pass_count=1, true_positives=2, invalid_runs=1
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert not decision.promotion_ready
    assert decision.final_winner == "king"
    assert decision.reason == "candidate did not beat the current SN60 king"


def test_evaluate_sn60_promotion_uses_pass_count_before_true_positives() -> None:
    king = build_variant(
        "king",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
    )
    candidate = build_variant(
        "candidate",
        aggregated_score=0.5,
        codebase_pass_count=2,
        true_positives=4,
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert decision.promotion_ready
    assert decision.final_winner == "candidate"


def test_evaluate_sn60_promotion_uses_true_positives_as_final_tiebreaker() -> None:
    king = build_variant(
        "king",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
    )
    candidate = build_variant(
        "candidate",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=6,
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert decision.promotion_ready
    assert decision.final_winner == "candidate"


def test_evaluate_sn60_promotion_uses_precision_tiebreaker() -> None:
    king = build_variant(
        "king",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
        total_found=8,
    )
    candidate = build_variant(
        "candidate",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
        total_found=5,
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert decision.promotion_ready
    assert decision.final_winner == "candidate"


def build_variant(
    variant_name: str,
    *,
    aggregated_score: float,
    codebase_pass_count: int,
    true_positives: int = 0,
    total_found: int | None = None,
    invalid_runs: int = 0,
) -> Sn60VariantSummary:
    found = true_positives if total_found is None else total_found
    precision = true_positives / found if found else 0.0
    f1_score = (
        2 * precision * aggregated_score / (precision + aggregated_score)
        if precision + aggregated_score > 0
        else 0.0
    )
    replica_results = [
        Sn60ReplicaResult(
            project_key="project-alpha",
            replica_index=1,
            report_path="/tmp/report.json",
            evaluation_path="/tmp/evaluation.json",
            execution_success=True,
            evaluation_status="success" if invalid_runs == 0 else "error",
            score=aggregated_score,
            detection_rate=aggregated_score,
            result="PASS" if codebase_pass_count else "FAIL",
            true_positives=true_positives,
            total_expected=4,
            total_found=found,
            precision=precision,
            f1_score=f1_score,
        )
    ]
    return Sn60VariantSummary(
        variant_name=variant_name,
        artifact_path=f"/tmp/{variant_name}",
        artifact_hash=f"{variant_name}-hash",
        successful_runs=1 - invalid_runs,
        invalid_runs=invalid_runs,
        pass_count=codebase_pass_count,
        codebase_pass_count=codebase_pass_count,
        aggregated_score=aggregated_score,
        average_detection_rate=aggregated_score,
        true_positives=true_positives,
        total_expected=4,
        total_found=found,
        precision=precision,
        f1_score=f1_score,
        project_summaries=[
            Sn60ProjectAggregate(
                project_key="project-alpha",
                replica_count=1,
                successful_runs=1 - invalid_runs,
                invalid_runs=invalid_runs,
                pass_count=codebase_pass_count,
                passed=bool(codebase_pass_count),
                average_detection_rate=aggregated_score,
                true_positives=true_positives,
                total_expected=4,
                total_found=found,
                precision=precision,
                f1_score=f1_score,
            )
        ],
        replica_results=replica_results,
    )


def _write_detection_bundle(root: Path, detection: float) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        f"# detection={detection}\n"
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': []}\n",
        encoding="utf-8",
    )


def _detection_hooks():
    """Hooks that read each staged bundle's encoded detection and score it, while
    counting how many times each variant actually executes."""
    ran: dict[str, int] = {}

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        ran[context.variant_name] = ran.get(context.variant_name, 0) + 1
        source = (Path(context.bundle_root) / "agent.py").read_text(encoding="utf-8")
        detection = 0.0
        for line in source.splitlines():
            if "# detection=" in line:
                detection = float(line.split("# detection=")[1].strip())
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [
                    {
                        "title": "Missing authorization",
                        "description": "A" * 80,
                        "severity": "high",
                        "file": "contracts/Vault.sol",
                    }
                ],
                "detection": detection,
            },
        }

    def evaluate(
        _context: Sn60ReplicaContext, report_payload: dict[str, object]
    ) -> dict[str, object]:
        detection = report_payload["report"]["detection"]
        return {
            "status": "success",
            "result": {
                "result": "PASS" if detection >= 1.0 else "FAIL",
                "detection_rate": detection,
                "true_positives": int(round(detection * 4)),
                "total_expected": 4,
                "total_found": 4,
                "precision": 1.0,
                "f1_score": detection,
            },
        }

    return ran, execute, evaluate


def test_run_sn60_challenge_ranks_candidates_and_picks_strict_winner(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    candidates = []
    for name, detection in (("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)):
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        candidates.append((name, str(path)))
    scoreboard = tmp_path / "king_scoreboard.json"
    progress_path = tmp_path / "challenge-progress.json"

    ran, execute, evaluate = _detection_hooks()
    result = _run_challenge(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-challenge-1",
        king_scoreboard_path=str(scoreboard),
        execution_hook=execute,
        evaluation_hook=evaluate,
        progress_path=str(progress_path),
    )

    # Live progress is published: by the end every candidate is scored and the
    # snapshot is marked completed with the winner.
    import json as _json

    progress = _json.loads(progress_path.read_text())
    assert progress["state"] == "completed"
    assert progress["winner_submission_id"] == "cand-c"
    assert {c["submission_id"] for c in progress["candidates"]} == {"cand-a", "cand-b", "cand-c"}
    assert all(c["done"] == c["total"] and c["state"] == "done" for c in progress["candidates"])
    # Each finished candidate carries its full result + per-problem breakdown, and
    # the king's result is published too (for the detail page).
    winner_entry = next(c for c in progress["candidates"] if c["submission_id"] == "cand-c")
    assert winner_entry["aggregated_score"] == 0.75
    assert winner_entry["beats_king"] is True
    assert isinstance(winner_entry["projects"], list) and winner_entry["projects"]
    assert progress["king"]["aggregated_score"] == 0.25
    assert isinstance(progress["king"]["projects"], list) and progress["king"]["projects"]

    # Ranked best-first by detection; the strict winner is the top one that beats the king.
    assert [entry.submission_id for entry in result.entries] == ["cand-c", "cand-b", "cand-a"]
    assert [entry.beats_king for entry in result.entries] == [True, True, False]
    assert result.winner_submission_id == "cand-c"
    assert result.promotion_ready is True
    assert result.king.aggregated_score == 0.25

    # The king was scored once for the challenge (cached), the three candidates each ran.
    assert ran["king"] == 1
    assert ran["candidate"] == 3
    assert (Path(result.output_root) / "challenge_result.json").exists()

    # The winner's promotion artifact is persisted from the duel it already ran,
    # so the king is promoted from this challenge -- no second duel at merge time.
    assert result.winner_challenge_summary_path is not None
    summary_path = Path(result.winner_challenge_summary_path)
    assert summary_path.exists()
    assert summary_path.name == "challenge_summary.json"


def test_run_sn60_challenge_optional_screener_skips_failed_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    candidates = []
    for name, detection in (("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)):
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        candidates.append((name, str(path)))
    monkeypatch.setenv("KATA_SN60_ENABLE_SCREENER_PROJECT", "1")
    monkeypatch.setenv("KATA_SN60_SCREENER_PROJECT_KEY", "project-alpha")
    ran: dict[str, int] = {}

    def bundle_detection(context: Sn60ReplicaContext) -> float:
        source = (Path(context.bundle_root) / "agent.py").read_text(encoding="utf-8")
        for line in source.splitlines():
            if "# detection=" in line:
                return float(line.split("# detection=")[1].strip())
        return 0.0

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        ran[context.variant_name] = ran.get(context.variant_name, 0) + 1
        detection = bundle_detection(context)
        if context.variant_name == "screening":
            if detection == 0.0:
                return {"success": False, "error": "candidate failed smoke run"}
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [
                    {
                        "title": "Missing authorization",
                        "description": "A" * 80,
                        "severity": "high",
                        "file": "contracts/Vault.sol",
                    }
                ],
                "detection": detection,
            },
        }

    def evaluate(
        _context: Sn60ReplicaContext, report_payload: dict[str, object]
    ) -> dict[str, object]:
        detection = report_payload["report"]["detection"]
        return {
            "status": "success",
            "result": {
                "result": "PASS" if detection >= 1.0 else "FAIL",
                "detection_rate": detection,
                "true_positives": int(round(detection * 4)),
                "total_expected": 4,
                "total_found": 4,
                "precision": 1.0,
                "f1_score": detection,
            },
        }

    result = _run_challenge(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-challenge-screener",
        king_scoreboard_path=str(tmp_path / "king_scoreboard.json"),
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    by_id = {entry.submission_id: entry for entry in result.entries}
    assert result.winner_submission_id == "cand-c"
    assert by_id["cand-a"].screening_result["status"] == "failed"
    assert by_id["cand-a"].duel_run_id.startswith("sn60-screening-")
    assert by_id["cand-a"].candidate.invalid_runs == 1
    assert by_id["cand-b"].screening_result["status"] == "passed"
    assert by_id["cand-c"].screening_result["status"] == "passed"
    assert ran["screening"] == 3
    # Each passing screener result is reused as the only project/replica score.
    assert ran.get("candidate", 0) == 0
    assert ran["king"] == 1


def test_run_sn60_challenge_completes_when_every_candidate_fails_screener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the execution screener rejects every candidate, no duel ever runs and the
    # king is never scored. The challenge must still resolve as a clean no-winner
    # result (king=None) rather than crashing on an assertion.
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    candidates = []
    for name in ("cand-a", "cand-b"):
        path = tmp_path / name
        _write_detection_bundle(path, 0.0)  # detection 0.0 -> screener fails
        candidates.append((name, str(path)))
    monkeypatch.setenv("KATA_SN60_ENABLE_SCREENER_PROJECT", "1")
    monkeypatch.setenv("KATA_SN60_SCREENER_PROJECT_KEY", "project-alpha")
    ran: dict[str, int] = {}

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        ran[context.variant_name] = ran.get(context.variant_name, 0) + 1
        if context.variant_name == "screening":
            return {"success": False, "error": "candidate failed smoke run"}
        return {"success": True, "report": {"vulnerabilities": [{"title": "v"}]}}

    result = _run_challenge(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-all-screened",
        king_scoreboard_path=str(tmp_path / "king_scoreboard.json"),
        execution_hook=execute,
        evaluation_hook=lambda context, report: {"status": "success", "result": {}},
    )

    assert result.king is None
    assert result.winner_submission_id is None
    assert result.promotion_ready is False
    assert {entry.submission_id for entry in result.entries} == {"cand-a", "cand-b"}
    assert all(entry.screening_result["status"] == "failed" for entry in result.entries)
    assert ran.get("candidate", 0) == 0  # no duel ran
    assert ran.get("king", 0) == 0  # king never scored
    # The challenge summary is written and re-readable with a null king.
    summary = json.loads(
        (tmp_path / "runs" / result.run_id / "challenge_result.json").read_text(encoding="utf-8")
    )
    assert summary["king"] is None


def test_run_sn60_challenge_has_no_winner_when_none_beats_king(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.5)
    candidates = []
    for name, detection in (("cand-a", 0.0), ("cand-b", 0.25)):
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        candidates.append((name, str(path)))

    _ran, execute, evaluate = _detection_hooks()
    result = _run_challenge(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-challenge-2",
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    assert result.winner_submission_id is None
    assert result.promotion_ready is False
    assert all(entry.beats_king is False for entry in result.entries)
    # No winner -> no promotion artifact to write.
    assert result.winner_challenge_summary_path is None


def test_run_sn60_challenge_rejects_duplicate_submission_ids(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    _write_detection_bundle(king_root, 0.25)
    _write_detection_bundle(candidate_root, 0.5)

    with pytest.raises(ValueError, match="Duplicate submission id"):
        _run_challenge(
            king_artifact_path=str(king_root),
            candidates=[("dup", str(candidate_root)), ("dup", str(candidate_root))],
            project_keys=["project-alpha"],
            output_root=str(tmp_path / "runs"),
            sandbox_root=str(sandbox_root),
            benchmark_file=str(benchmark_path),
            sandbox_commit="commit-challenge-3",
        )
