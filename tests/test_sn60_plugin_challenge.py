"""Phase 3b tests: a full SN60 challenge through the generic orchestrator.

``run_sn60_plugin_challenge`` must produce a ``Sn60ChallengeResult`` whose *contract* fields
(winner, ranking, per-variant scores, king summary, sandbox source, project keys) match
the legacy ``run_sn60_challenge`` exactly. Internal artifact paths, run ids and timestamps
are allowed to differ (they are not part of the consumed contract).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60 import Sn60BitsecPlugin, run_sn60_plugin_challenge


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

def test_run_sn60_plugin_challenge_writes_board_progress(tmp_path: Path) -> None:
    # The plugin challenge must write challenge-progress.json in the same shape the board
    # reads today (king + per-candidate entries, per-problem breakdowns, winner).
    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()
    progress_path = tmp_path / "challenge-progress.json"

    run_sn60_plugin_challenge(
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


def test_run_sn60_plugin_challenge_reuses_passed_screener_as_first_replica(
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
    result = run_sn60_plugin_challenge(
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


def test_run_sn60_plugin_challenge_no_winner_when_king_unbeaten(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.9)  # tp = 4, unbeatable here
    weak = tmp_path / "weak"
    _write_detection_bundle(weak, 0.1)  # tp = 0
    execute, evaluate = _detection_hooks()

    result = run_sn60_plugin_challenge(
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


def test_run_sn60_plugin_challenge_always_writes_candidate_summary_for_loser(
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

    result = run_sn60_plugin_challenge(
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
def test_run_sn60_plugin_challenge_rejects_unsafe_submission_id(
    tmp_path: Path, submission_id: str
) -> None:
    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    with pytest.raises(ValueError, match="path-safe identifier"):
        run_sn60_plugin_challenge(
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


def test_run_sn60_plugin_challenge_rejects_duplicate_submission_ids(tmp_path: Path) -> None:
    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    with pytest.raises(ValueError, match="Duplicate submission id"):
        run_sn60_plugin_challenge(
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


def test_run_sn60_plugin_challenge_rejects_unknown_project_key(tmp_path: Path) -> None:
    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    with pytest.raises(ValueError, match="not present in the resolved benchmark snapshot"):
        run_sn60_plugin_challenge(
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


# --- judge budget lifecycle ---------------------------------------------------------------------


def test_a_challenge_without_a_judge_budget_reports_no_judge_usage(tmp_path: Path) -> None:
    """Unmetered stays the default, and ``judge_usage: None`` is the operator-visible signal for
    it rather than a silent absence."""
    from kata_sn60.cli import sn60_challenge_result_json

    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    result = run_sn60_plugin_challenge(
        king_artifact_path=str(king_root),
        candidates=[("cand-a", paths["cand-a"])],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-unmetered",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "unmetered"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
    )

    assert result.judge_usage is None
    assert sn60_challenge_result_json(result)["judge_usage"] is None


def test_a_metered_challenge_publishes_what_the_judge_cost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kata_sn60.cli import sn60_challenge_result_json

    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, _ = _detection_hooks()

    monkeypatch.setenv("KATA_SN60_JUDGE_MAX_CALLS", "50")
    monkeypatch.setenv("KATA_SN60_JUDGE_MAX_OUTPUT_TOKS", "256")

    seen_gateways = []

    def evaluate(context, report_payload):
        # Stand in for the scorer: charge the meter the way a real judge call would.
        gateway = plugin._active_judge_gateway
        seen_gateways.append(gateway)
        hold = gateway.meter.reserve(request_chars=400)
        gateway.meter.settle(hold, input_tokens=300, output_tokens=120, cached_tokens=40)
        return {
            "status": "success",
            "result": {
                "result": "PASS",
                "detection_rate": 1.0,
                "true_positives": 4,
                "total_expected": 4,
                "total_found": 4,
                "precision": 1.0,
                "f1_score": 1.0,
            },
        }

    plugin = Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate)

    result = run_sn60_plugin_challenge(
        king_artifact_path=str(king_root),
        candidates=[("cand-a", paths["cand-a"])],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-metered",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "metered"),
        plugin=plugin,
    )

    # One gateway spans the WHOLE challenge -- king and candidate -- because the budget is
    # per challenge, not per variant.
    assert len(seen_gateways) == 2
    assert seen_gateways[0] is seen_gateways[1]

    usage = result.judge_usage
    assert usage["calls"] == 2
    assert usage["input_tokens"] == 600
    assert usage["output_tokens"] == 240
    assert usage["total_tokens"] == 840
    assert usage["refusals"] == 0

    # It reaches the published result, and survives the round trip through the file on disk.
    assert sn60_challenge_result_json(result)["judge_usage"]["calls"] == 2
    written = json.loads(
        (Path(result.output_root) / "challenge_result.json").read_text(encoding="utf-8")
    )
    assert written["judge_usage"]["calls"] == 2

    # The gateway is torn down with the challenge.
    assert plugin._active_judge_gateway is None


def test_a_judge_protocol_error_prevents_challenge_result_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kata_sn60.execution.judge_gateway import JudgeProtocolError

    sandbox_root, benchmark_path, king_root, _specs, paths = _build_inputs(tmp_path)
    execute, _ = _detection_hooks()
    monkeypatch.setenv("KATA_SN60_JUDGE_MAX_CALLS", "50")

    def evaluate(context, report_payload):
        plugin._active_judge_gateway.meter.record_protocol_error(
            "missing or malformed x-job-run-id"
        )
        return {
            "status": "success",
            "result": {
                "result": "PASS",
                "detection_rate": 1.0,
                "true_positives": 1,
                "total_expected": 1,
                "total_found": 1,
                "precision": 1.0,
                "f1_score": 1.0,
            },
        }

    plugin = Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate)
    output_root = tmp_path / "protocol-failure"
    with pytest.raises(JudgeProtocolError, match="attribution protocol failed"):
        run_sn60_plugin_challenge(
            king_artifact_path=str(king_root),
            candidates=[("cand-a", paths["cand-a"])],
            config={
                "sandbox_root": str(sandbox_root),
                "benchmark_file": str(benchmark_path),
                "sandbox_commit": "commit-protocol-failure",
                "project_keys": ["project-alpha"],
                "replicas_per_project": 1,
            },
            output_root=str(output_root),
            plugin=plugin,
        )

    assert not list(output_root.rglob("challenge_result.json"))


def test_the_capacity_estimate_bounds_judge_spend_when_the_lane_configures_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``capacity.restrict_to_configured`` DEFERS when a configured day cap has no bound here, so
    this is what makes KATA_SUBNET_BUDGET_INFERENCE_CALLS enforceable rather than a deferral."""
    monkeypatch.setenv("KATA_SN60_JUDGE_MAX_CALLS", "400")
    monkeypatch.setenv("KATA_SN60_JUDGE_MAX_OUTPUT_TOKS", "1000")
    monkeypatch.setenv("KATA_SN60_JUDGE_MAX_REQUEST_CHARS", "2000")

    bounds = Sn60BitsecPlugin().capacity_estimate(
        config={"project_keys": ["p"], "replicas_per_project": 1}
    )

    assert bounds["inference_calls"] == 400.0
    assert bounds["tokens"] == 400 * 2000 + 400 * 1000
    assert bounds["tee_runs"] > 0


def test_the_capacity_estimate_declares_no_judge_bound_when_unconfigured() -> None:
    bounds = Sn60BitsecPlugin().capacity_estimate(
        config={"project_keys": ["p"], "replicas_per_project": 1}
    )

    assert set(bounds) == {"tee_runs"}


def test_the_published_result_records_which_proxy_answered(tmp_path: Path) -> None:
    """A score is only as attributable as the container that produced it. The record rides with the
    result -- including when the deployment is unpinned, so 'we could not tell' is auditable after
    the fact rather than remembered."""
    from kata_sn60.cli import sn60_challenge_result_json

    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    result = run_sn60_plugin_challenge(
        king_artifact_path=str(king_root),
        candidates=[("cand-a", paths["cand-a"])],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-proxy",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "proxy"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
    )

    record = result.proxy_image
    assert record is not None
    assert set(record) >= {"container", "image_digest", "pinned_digest", "sandbox_commit",
                           "sandbox_tree_sha256", "verified", "reason"}
    assert sn60_challenge_result_json(result)["proxy_image"] == record
    written = json.loads(
        (Path(result.output_root) / "challenge_result.json").read_text(encoding="utf-8")
    )
    assert written["proxy_image"] == record


# --- the board must say what is actually happening -----------------------------------------------


def test_the_board_reports_the_screening_gate_instead_of_a_king_that_is_not_scoring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What made the gate look frozen. The writer opened with king ``scoring`` before anything was
    scored, and published nothing during the gate -- so a room run that legitimately takes minutes
    was indistinguishable from a hang, on a board asserting work that had not begun."""
    from kata_sn60.progress import Sn60ChallengeProgress

    path = tmp_path / "challenge-progress.json"
    writer = Sn60ChallengeProgress(
        run_id="r1", project_keys=["p"], candidate_labels=["cand-a"],
        per_variant_total=21, progress_path=str(path),
    )

    opened = json.loads(path.read_text(encoding="utf-8"))
    assert opened["stage"] == "screening"
    assert opened["king"]["state"] == "pending"      # NOT "scoring"

    writer.mark_screening("cand-a", started_at="2026-07-30T01:15:06+00:00", timeout_seconds=1020.0)
    during = json.loads(path.read_text(encoding="utf-8"))
    entry = during["candidates"][0]
    assert during["stage"] == "screening"
    assert entry["state"] == "screening"
    # Elapsed-against-budget is the only honest progress: the gate is one room run with no ticks.
    assert entry["screening_started_at"] == "2026-07-30T01:15:06+00:00"
    assert entry["screening_timeout_seconds"] == 1020.0
    assert during["king"]["state"] == "pending"

    writer.mark_screening_passed("cand-a", finished_at="2026-07-30T01:22:00+00:00")
    writer.mark_scoring_started()
    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["stage"] == "scoring"
    assert after["king"]["state"] == "scoring"       # true only now
    assert after["candidates"][0]["state"] == "queued"


def test_a_challenge_publishes_the_gate_then_scoring(tmp_path: Path) -> None:
    """End to end through the real driver: the board passes through the screening stage and only
    then reports scoring."""
    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()
    progress_path = tmp_path / "challenge-progress.json"

    run_sn60_plugin_challenge(
        king_artifact_path=str(king_root),
        candidates=[("cand-a", paths["cand-a"])],
        config={
            "sandbox_root": str(sandbox_root), "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-gate", "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "gate"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
        progress_path=str(progress_path),
    )

    final = json.loads(progress_path.read_text(encoding="utf-8"))
    assert final["state"] == "completed"
    # The gate is disabled in this configuration, so it is passed through rather than dwelt in --
    # but the stage must still have advanced off "screening" rather than being left there.
    assert final["stage"] == "scoring"
    assert final["king"]["state"] == "done"
