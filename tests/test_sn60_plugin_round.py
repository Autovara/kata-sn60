"""Phase 3b tests: a full SN60 round through the generic orchestrator.

``run_sn60_plugin_round`` must produce a ``Sn60RoundResult`` whose *contract* fields
(winner, ranking, per-variant scores, king summary, sandbox source, project keys) match
the legacy ``run_sn60_round`` exactly. Internal artifact paths, run ids and timestamps
are allowed to differ (they are not part of the consumed contract).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60 import Sn60BitsecPlugin, run_sn60_plugin_round


def _write_detection_bundle(root: Path, detection: float) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        f"# detection={detection}\n"
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': []}\n",
        encoding="utf-8",
    )


def _write_benchmark(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps([{"project_id": "project-alpha", "vulnerabilities": [{"title": "expected"}]}])
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def _detection_hooks():
    def execute(context) -> dict[str, object]:
        source = (Path(context.bundle_root) / "agent.py").read_text(encoding="utf-8")
        detection = 0.0
        for line in source.splitlines():
            if "# detection=" in line:
                detection = float(line.split("# detection=")[1].strip())
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [{"title": "v"}],
                "detection": detection,
            },
        }

    def evaluate(_context, report_payload: dict[str, object]) -> dict[str, object]:
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

    return execute, evaluate


def _variant_contract(summary) -> dict:
    return {
        "true_positives": summary.true_positives,
        "aggregated_score": summary.aggregated_score,
        "codebase_pass_count": summary.codebase_pass_count,
        "precision": summary.precision,
        "f1_score": summary.f1_score,
        "invalid_runs": summary.invalid_runs,
        "artifact_hash": summary.artifact_hash,
    }


def _sandbox_contract(source) -> dict:
    return {
        "benchmark_sha256": source.benchmark_sha256,
        "sandbox_commit": source.sandbox_commit,
        "scorer_version": source.scorer_version,
    }


def _build_inputs(tmp_path: Path):
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    specs = [("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)]
    paths = {}
    for name, detection in specs:
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        paths[name] = str(path)
    return sandbox_root, benchmark_path, king_root, specs, paths

def test_run_sn60_plugin_round_writes_board_progress(tmp_path: Path) -> None:
    # The plugin round must write round-progress.json in the same shape the board
    # reads today (king + per-candidate entries, per-problem breakdowns, winner).
    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()
    progress_path = tmp_path / "round-progress.json"

    run_sn60_plugin_round(
        king_artifact_path=str(king_root),
        candidates=[(name, paths[name]) for name, _ in specs],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-progress",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "generic"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
        progress_path=str(progress_path),
    )

    progress = json.loads(progress_path.read_text(encoding="utf-8"))
    assert progress["state"] == "completed"
    assert progress["winner_submission_id"] == "cand-c"
    assert {c["submission_id"] for c in progress["candidates"]} == {
        "cand-a",
        "cand-b",
        "cand-c",
    }
    assert all(c["done"] == c["total"] and c["state"] == "done" for c in progress["candidates"])
    winner = next(c for c in progress["candidates"] if c["submission_id"] == "cand-c")
    assert winner["aggregated_score"] == 0.75
    assert winner["beats_king"] is True
    assert isinstance(winner["projects"], list) and winner["projects"]
    # The king is scored and published for the detail view.
    assert progress["king"]["state"] == "done"
    assert progress["king"]["aggregated_score"] == 0.25
    assert isinstance(progress["king"]["projects"], list) and progress["king"]["projects"]


def test_run_sn60_plugin_round_reuses_passed_screener_as_first_replica(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    base_execute, evaluate = _detection_hooks()
    calls: list[tuple[str, str, int]] = []

    def execute(context):
        calls.append((context.variant_name, context.project_key, context.replica_index))
        payload = base_execute(context)
        # The admission gate accepts an actual scoring-shaped report. Include the
        # screening-required finding fields while retaining the test's detection
        # value used by the evaluator.
        payload["report"]["vulnerabilities"] = [
            {
                "title": "Missing authorization",
                "description": "A" * 80,
                "severity": "high",
                "file": "contracts/Vault.sol",
            }
        ]
        return payload

    monkeypatch.setenv("KATA_SN60_ENABLE_SCREENER_PROJECT", "true")
    result = run_sn60_plugin_round(
        king_artifact_path=str(king_root),
        candidates=[("cand-a", paths["cand-a"])],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-reuse",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 2,
        },
        output_root=str(tmp_path / "generic"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
    )

    assert calls.count(("screening", "project-alpha", 1)) == 1
    assert ("candidate", "project-alpha", 1) not in calls
    assert calls.count(("candidate", "project-alpha", 2)) == 1
    assert result.entries[0].candidate.successful_runs == 2


def test_run_sn60_plugin_round_no_winner_when_king_unbeaten(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.9)  # tp = 4, unbeatable here
    weak = tmp_path / "weak"
    _write_detection_bundle(weak, 0.1)  # tp = 0
    execute, evaluate = _detection_hooks()

    result = run_sn60_plugin_round(
        king_artifact_path=str(king_root),
        candidates=[("weak", str(weak))],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-x",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "generic"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
    )
    assert result.winner_submission_id is None
    assert result.promotion_ready is False
    assert result.promotion_reason == "no candidate beat the current SN60 king"
    assert result.winner_challenge_summary_path is None
    assert result.entries[0].beats_king is False


def test_run_sn60_plugin_round_always_writes_candidate_summary_for_loser(
    tmp_path: Path,
) -> None:
    # Continuous mode: even when the candidate loses this challenge's fresh king, its
    # challenge summary must be written so the caller can still promote it off the
    # king's running average. winner_submission_id/promotion_ready stay unchanged.
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.9)  # tp = 4, unbeaten this challenge
    weak = tmp_path / "weak"
    _write_detection_bundle(weak, 0.1)  # tp = 0
    execute, evaluate = _detection_hooks()

    result = run_sn60_plugin_round(
        king_artifact_path=str(king_root),
        candidates=[("weak", str(weak))],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-continuous",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
            "always_write_candidate_summary": True,
        },
        output_root=str(tmp_path / "generic"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
    )

    # The engine still reports no fresh-duel winner ...
    assert result.winner_submission_id is None
    assert result.promotion_ready is False
    assert result.entries[0].beats_king is False
    # ... but the loser's challenge summary was written and is loadable.
    assert result.winner_challenge_summary_path is not None
    summary_path = Path(result.winner_challenge_summary_path)
    assert summary_path.exists()
    assert summary_path.parent.name == "weak"  # the candidate's own run root


@pytest.mark.parametrize("submission_id", ["../escape", "nested/id", ".", " candidate"])
def test_run_sn60_plugin_round_rejects_unsafe_submission_id(
    tmp_path: Path, submission_id: str
) -> None:
    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    with pytest.raises(ValueError, match="path-safe identifier"):
        run_sn60_plugin_round(
            king_artifact_path=str(king_root),
            candidates=[(submission_id, paths["cand-a"])],
            config={
                "sandbox_root": str(sandbox_root),
                "benchmark_file": str(benchmark_path),
                "sandbox_commit": "commit-safe-id",
                "project_keys": ["project-alpha"],
                "replicas_per_project": 1,
            },
            output_root=str(tmp_path / "generic"),
            plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
        )


def test_run_sn60_plugin_round_rejects_duplicate_submission_ids(tmp_path: Path) -> None:
    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    with pytest.raises(ValueError, match="Duplicate submission id"):
        run_sn60_plugin_round(
            king_artifact_path=str(king_root),
            candidates=[("duplicate", paths["cand-a"]), ("duplicate", paths["cand-b"])],
            config={
                "sandbox_root": str(sandbox_root),
                "benchmark_file": str(benchmark_path),
                "sandbox_commit": "commit-duplicate",
                "project_keys": ["project-alpha"],
                "replicas_per_project": 1,
            },
            output_root=str(tmp_path / "generic"),
            plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
        )


def test_run_sn60_plugin_round_rejects_unknown_project_key(tmp_path: Path) -> None:
    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    with pytest.raises(ValueError, match="not present in the resolved benchmark snapshot"):
        run_sn60_plugin_round(
            king_artifact_path=str(king_root),
            candidates=[("candidate", paths["cand-a"])],
            config={
                "sandbox_root": str(sandbox_root),
                "benchmark_file": str(benchmark_path),
                "sandbox_commit": "commit-project-key",
                "project_keys": ["../../escape"],
                "replicas_per_project": 1,
            },
            output_root=str(tmp_path / "generic"),
            plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
        )
