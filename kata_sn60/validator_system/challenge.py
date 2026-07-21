from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from kata.provenance import short_hash
from kata.state.lanes import (
    BENCHMARK_SNAPSHOT_SCHEMA_VERSION,
    CHALLENGE_STATE_SCHEMA_VERSION,
    PROMOTION_RECORD_SCHEMA_VERSION,
    BenchmarkSnapshotState,
    ChallengeState,
    PromotionRecord,
    write_benchmark_snapshot,
    write_challenge_state,
    write_promotion_record,
)

from kata_sn60.execution.policy import tee_execution_enabled
from kata_sn60.sn60_bitsec import (
    DEFAULT_EVAL_MAX_VULNS,
    DEFAULT_REPLICAS_PER_PROJECT,
    Sn60DuelSummary,
    Sn60EvaluationHook,
    Sn60ExecutionHook,
    Sn60ReplicaResult,
    Sn60SandboxSource,
    Sn60VariantSummary,
    bitsec_project_image,
    build_default_evaluation_hook,
    build_default_execution_hook,
    hash_bundle_root,
    resolve_sn60_sandbox_source,
    score_variant_on_projects,
    sn60_f1_score,
    summarize_variant,
    validate_sn60_project_keys,
)
from kata_sn60.validator_system.screening import (
    Sn60ScreeningResult,
    run_sn60_screening,
)

SN60_MINER_LANE_ID = "sn60__bitsec"
SN60_MINER_MODE = "miner"
SN60_VALIDATOR_MODEL = "sn60-bitsec-sandbox"
CHALLENGE_SUMMARY_SCHEMA_VERSION = 5
SN60_ENABLE_SCREENER_PROJECT_ENV = "KATA_SN60_ENABLE_SCREENER_PROJECT"
SN60_SCREENER_PROJECT_KEY_ENV = "KATA_SN60_SCREENER_PROJECT_KEY"


@dataclass(frozen=True)
class ChallengePoolSummary:
    project_keys: list[str]
    run_summary_path: str
    total_task_weight: float
    variant_successes: dict[str, int]
    variant_invalid_runs: dict[str, int]
    variant_scores: dict[str, float]
    variant_detection_scores: dict[str, float]
    candidate_beats_king: bool
    candidate_score_delta: float
    competition_mode: str = "king_duel"


@dataclass(frozen=True)
class ChallengeSummary:
    schema_version: int
    run_id: str
    manifest_path: str
    mode: str
    evaluator_version: str
    validator_model: str
    king_artifact: str
    candidate_artifact: str
    king_artifact_hash: str
    candidate_artifact_hash: str
    primary_pool_fingerprint: str | None
    created_at: str
    primary: ChallengePoolSummary
    promotion_ready: bool
    promotion_reason: str


@dataclass(frozen=True)
class Sn60PromotionDecision:
    promotion_ready: bool
    final_winner: str
    reason: str


def sn60_duel_to_challenge_summary(
    duel_summary: Sn60DuelSummary,
    *,
    lane_id: str = SN60_MINER_LANE_ID,
    screening_result: dict[str, object] | None = None,
) -> ChallengeSummary:
    decision = evaluate_sn60_promotion(
        king=duel_summary.king,
        candidate=duel_summary.candidate,
        screening_result=screening_result,
    )
    freshness_fingerprint = sn60_freshness_fingerprint(duel_summary)
    duel_summary_path = Path(duel_summary.output_root) / "duel_summary.json"
    return ChallengeSummary(
        schema_version=CHALLENGE_SUMMARY_SCHEMA_VERSION,
        run_id=duel_summary.run_id,
        manifest_path=str(duel_summary_path),
        mode=SN60_MINER_MODE,
        evaluator_version=sn60_evaluator_version(duel_summary),
        validator_model=SN60_VALIDATOR_MODEL,
        king_artifact=duel_summary.king.artifact_path,
        candidate_artifact=duel_summary.candidate.artifact_path,
        king_artifact_hash=duel_summary.king.artifact_hash,
        candidate_artifact_hash=duel_summary.candidate.artifact_hash,
        primary_pool_fingerprint=freshness_fingerprint,
        created_at=duel_summary.created_at,
        primary=sn60_duel_to_pool_summary(
            duel_summary,
            run_summary_path=duel_summary_path,
            screening_result=screening_result,
        ),
        promotion_ready=decision.promotion_ready,
        promotion_reason=f"{lane_id}: {decision.reason}",
    )


def sn60_duel_to_pool_summary(
    duel_summary: Sn60DuelSummary,
    *,
    run_summary_path: Path,
    screening_result: dict[str, object] | None = None,
) -> ChallengePoolSummary:
    king_score = round(sn60_pass_score(duel_summary.king) * 100, 2)
    candidate_score = round(sn60_pass_score(duel_summary.candidate) * 100, 2)
    king_detection = round(duel_summary.king.aggregated_score * 100, 2)
    candidate_detection = round(duel_summary.candidate.aggregated_score * 100, 2)
    decision = evaluate_sn60_promotion(
        king=duel_summary.king,
        candidate=duel_summary.candidate,
        screening_result=screening_result,
    )
    return ChallengePoolSummary(
        project_keys=list(duel_summary.project_keys),
        run_summary_path=str(run_summary_path),
        total_task_weight=float(len(duel_summary.project_keys)),
        variant_successes={
            "king": duel_summary.king.codebase_pass_count,
            "candidate": duel_summary.candidate.codebase_pass_count,
        },
        variant_invalid_runs={
            "king": duel_summary.king.invalid_runs,
            "candidate": duel_summary.candidate.invalid_runs,
        },
        variant_scores={
            "king": king_score,
            "candidate": candidate_score,
        },
        variant_detection_scores={
            "king": king_detection,
            "candidate": candidate_detection,
        },
        candidate_beats_king=decision.final_winner == "candidate",
        candidate_score_delta=round(candidate_score - king_score, 2),
    )


def failed_candidate_variant_summary(
    *,
    candidate_artifact_path: str,
    candidate_artifact_hash: str,
) -> Sn60VariantSummary:
    return Sn60VariantSummary(
        variant_name="candidate",
        artifact_path=str(Path(candidate_artifact_path).expanduser().resolve()),
        artifact_hash=candidate_artifact_hash,
        successful_runs=0,
        invalid_runs=1,
        pass_count=0,
        codebase_pass_count=0,
        aggregated_score=0.0,
        average_detection_rate=0.0,
        true_positives=0,
        total_expected=0,
        total_found=0,
        precision=0.0,
        f1_score=0.0,
        project_summaries=[],
        replica_results=[],
    )


def evaluate_sn60_promotion(
    *,
    king: Sn60VariantSummary,
    candidate: Sn60VariantSummary,
    screening_result: dict[str, object] | None = None,
) -> Sn60PromotionDecision:
    screening_status = screening_result.get("status") if screening_result is not None else None
    if screening_result is not None and screening_status not in {"passed", "pass", True}:
        return Sn60PromotionDecision(
            promotion_ready=False,
            final_winner="king",
            reason="candidate failed SN60 screening",
        )
    candidate_rank = sn60_variant_rank(candidate)
    king_rank = sn60_variant_rank(king)
    if candidate_rank <= king_rank:
        return Sn60PromotionDecision(
            promotion_ready=False,
            final_winner="king",
            reason="candidate did not beat the current SN60 king",
        )
    return Sn60PromotionDecision(
        promotion_ready=True,
        final_winner="candidate",
        reason="candidate beat the current SN60 king",
    )


def sn60_screener_project_enabled() -> bool:
    value = os.environ.get(SN60_ENABLE_SCREENER_PROJECT_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_sn60_screener_project_key(project_keys: list[str]) -> str:
    configured = os.environ.get(SN60_SCREENER_PROJECT_KEY_ENV, "").strip()
    if configured:
        return configured
    if not project_keys:
        raise ValueError("SN60 screener project requires at least one project key.")
    return project_keys[0]


def run_optional_sn60_screener_project(
    *,
    candidate_artifact_path: str,
    project_keys: list[str],
    output_root: str,
    sandbox_source: Sn60SandboxSource,
    execution_hook: Sn60ExecutionHook | None,
) -> Sn60ScreeningResult | None:
    if not sn60_screener_project_enabled():
        return None
    screener_project_key = resolve_sn60_screener_project_key(project_keys)
    validate_sn60_project_keys([screener_project_key], sandbox_source=sandbox_source)
    return run_sn60_screening(
        candidate_artifact_path=candidate_artifact_path,
        project_key=screener_project_key,
        output_root=output_root,
        sandbox_source=sandbox_source,
        execution_hook=execution_hook,
        run_static_checks=False,
        require_findings=False,
    )


def sn60_pass_score(summary: Sn60VariantSummary) -> float:
    total_projects = len(summary.project_summaries)
    return summary.codebase_pass_count / total_projects if total_projects else 0.0


def project_pass_threshold_label(replicas_per_project: int) -> str:
    """The NOMINAL project-pass threshold, for display only.

    This is the bar when every replica succeeds. The effective rule
    (``project_passes``) is a >=2/3 majority of the SUCCESSFUL replicas: invalid
    (infra-failed) runs are excluded from the denominator, so with a flaked
    replica the real bar can be e.g. 2-of-2 rather than this nominal 2-of-3. It is
    a challenge-level policy summary and does not vary per project.
    """
    if replicas_per_project <= 0:
        return "invalid"
    required = (replicas_per_project * 2 + 2) // 3
    return f"{required}_of_{replicas_per_project}"


def sn60_variant_rank(
    summary: Sn60VariantSummary,
) -> tuple[float, int, int, int, float, float]:
    # SN60-compatible comparator: codebase pass/fail score first. Detection
    # remains a diagnostic metric, not the promotion score.
    return (
        round(sn60_pass_score(summary), 8),
        summary.codebase_pass_count,
        summary.true_positives,
        -summary.invalid_runs,
        round(summary.precision, 8),
        round(summary.f1_score, 8),
    )


DEFAULT_SN60_CHALLENGE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Sn60ChallengeEntry:
    submission_id: str
    artifact_path: str
    artifact_hash: str
    beats_king: bool | None
    duel_run_id: str
    candidate: Sn60VariantSummary
    selected_winner: bool = False
    screening_result: dict[str, object] | None = None


@dataclass(frozen=True)
class Sn60ChallengeResult:
    schema_version: int
    run_id: str
    created_at: str
    output_root: str
    project_keys: list[str]
    replicas_per_project: int
    sandbox_source: Sn60SandboxSource
    king: Sn60VariantSummary | None
    entries: list[Sn60ChallengeEntry]
    winner_submission_id: str | None
    promotion_ready: bool
    promotion_reason: str
    winner_challenge_summary_path: str | None = None
    competition_mode: str = "king_duel"


@dataclass(frozen=True)
class Sn60BaselineResult:
    schema_version: int
    run_id: str
    created_at: str
    output_root: str
    project_keys: list[str]
    replicas_per_project: int
    sandbox_source: Sn60SandboxSource
    submission_id: str
    artifact_path: str
    artifact_hash: str
    baseline: Sn60VariantSummary
    competition_mode: str = "baseline_only"


def build_sn60_challenge_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"sn60-challenge-{timestamp}-{secrets.token_hex(3)}"


def _write_sn60_result_json(path: Path, result: object) -> None:
    """Serialize an SN60 result dataclass (challenge or baseline) to JSON.

    Both results carry ``replicas_per_project`` and share the exact same on-disk
    shape and annotations, so the serialization lives in one place.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(result)
    payload["validator_replica_count"] = 1
    payload["runs_per_project"] = result.replicas_per_project
    payload["project_pass_threshold"] = project_pass_threshold_label(result.replicas_per_project)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_sn60_challenge_result(path: Path, result: Sn60ChallengeResult) -> None:
    _write_sn60_result_json(path, result)


def write_sn60_baseline_summary(path: Path, result: Sn60BaselineResult) -> None:
    _write_sn60_result_json(path, result)


def _sn60_variant_progress(summary: Sn60VariantSummary) -> dict[str, object]:
    """Full per-variant result (scores + per-problem breakdown) for the live
    progress feed, so the dashboard detail page can show a finished PR's — and the
    cached king's — complete duel result the moment it lands."""
    return {
        "aggregated_score": summary.aggregated_score,
        "detection_score": summary.aggregated_score,
        "sn60_pass_score": sn60_pass_score(summary),
        "true_positives": summary.true_positives,
        "total_expected": summary.total_expected,
        "total_found": summary.total_found,
        "precision": summary.precision,
        "f1_score": summary.f1_score,
        "invalid_runs": summary.invalid_runs,
        "codebase_pass_count": summary.codebase_pass_count,
        "projects": [
            {
                "project_key": project.project_key,
                "passed": project.passed,
                "detection_rate": project.average_detection_rate,
                "true_positives": project.true_positives,
                "total_expected": project.total_expected,
                "total_found": project.total_found,
                "precision": project.precision,
                "f1_score": project.f1_score,
            }
            for project in summary.project_summaries
        ],
    }


def _write_progress_atomic(progress: dict[str, object], progress_path: str | None) -> None:
    """Write the live challenge-progress file atomically.

    The dashboard polls this file, and problems now finish in bursts, so a plain
    write could be read half-serialized. Write to a temp sibling and rename
    (atomic on the same filesystem).
    """
    if not progress_path:
        return
    progress["updated_at"] = datetime.now(UTC).isoformat()
    path = Path(progress_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(progress, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


def _apply_running_metrics(
    target: dict[str, object], acc: dict, replica_result: Sn60ReplicaResult
) -> None:
    """Fold one replica result into a variant's running metric accumulator.

    Accumulates detection/precision/F1 and a growing per-problem list for whichever
    variant is scoring, so the dashboard detail pages (king AND each candidate) fill
    their metric bars and problem rows live, not only at the end.
    """
    acc["tp"] += replica_result.true_positives
    acc["expected"] += replica_result.total_expected
    acc["found"] += replica_result.total_found
    if replica_result.evaluation_status != "success":
        acc["invalid"] += 1
    acc["projects"].append(
        {
            "project_key": replica_result.project_key,
            "passed": replica_result.result == "PASS",
            "detection_rate": replica_result.detection_rate,
            "true_positives": replica_result.true_positives,
            "total_expected": replica_result.total_expected,
            "total_found": replica_result.total_found,
            "precision": replica_result.precision,
            "f1_score": replica_result.f1_score,
        }
    )
    detection = acc["tp"] / acc["expected"] if acc["expected"] else 0.0
    precision = acc["tp"] / acc["found"] if acc["found"] else 0.0
    f1 = sn60_f1_score(precision, detection)
    target["aggregated_score"] = detection
    target["precision"] = precision
    target["f1_score"] = f1
    target["true_positives"] = acc["tp"]
    target["total_expected"] = acc["expected"]
    target["total_found"] = acc["found"]
    target["invalid_runs"] = acc["invalid"]
    target["projects"] = list(acc["projects"])


def run_sn60_baseline_only(
    *,
    submission_id: str,
    artifact_path: str,
    project_keys: list[str],
    output_root: str | None = None,
    replicas_per_project: int = DEFAULT_REPLICAS_PER_PROJECT,
    sandbox_root: str | None = None,
    benchmark_file: str | None = None,
    sandbox_commit: str | None = None,
    execution_hook: Sn60ExecutionHook | None = None,
    evaluation_hook: Sn60EvaluationHook | None = None,
) -> Sn60BaselineResult:
    """Score one proof-only external baseline without evaluating any Kata king.

    This is intentionally not a competition challenge. It exists so operators can
    compare a public SN60 agent against a saved Kata challenge result without spending
    tokens re-running the already-scored Kata king/winner.
    """
    if not project_keys:
        raise ValueError("SN60 baseline replay requires at least one project key.")
    if replicas_per_project <= 0:
        raise ValueError("SN60 baseline replay replicas_per_project must be positive.")

    source = resolve_sn60_sandbox_source(
        sandbox_root=sandbox_root,
        benchmark_file=benchmark_file,
        sandbox_commit=sandbox_commit,
        scorer_version="ScaBenchScorerV2",
    )
    validate_sn60_project_keys(project_keys, sandbox_source=source)
    baseline_root = Path(artifact_path).expanduser().resolve()
    baseline_hash = hash_bundle_root(baseline_root)
    output_base = (
        Path(output_root).expanduser().resolve() if output_root else Path("runs").resolve()
    )
    run_id = build_sn60_challenge_id()
    run_root = output_base / run_id
    run_root.mkdir(parents=True, exist_ok=False)

    results = score_variant_on_projects(
        run_id=run_id,
        run_root=run_root,
        variant_name="baseline",
        artifact_root=baseline_root,
        project_keys=project_keys,
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        execution_hook=execution_hook
        or build_default_execution_hook(source, use_tee=tee_execution_enabled()),
        evaluation_hook=evaluation_hook or build_default_evaluation_hook(source),
        eval_max_vulns=DEFAULT_EVAL_MAX_VULNS,
        progress_callback=None,
    )
    baseline_summary = summarize_variant(
        variant_name="baseline",
        artifact_root=baseline_root,
        artifact_hash=baseline_hash,
        replica_results=results,
    )
    result = Sn60BaselineResult(
        schema_version=DEFAULT_SN60_CHALLENGE_SCHEMA_VERSION,
        run_id=run_id,
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(run_root),
        project_keys=list(project_keys),
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        submission_id=submission_id,
        artifact_path=str(baseline_root),
        artifact_hash=baseline_hash,
        baseline=baseline_summary,
    )
    write_sn60_baseline_summary(run_root / "baseline_summary.json", result)
    return result


def record_sn60_lane_provenance(
    *,
    lane_id: str,
    candidate_submission_id: str,
    duel_summary: Sn60DuelSummary,
    screening_result: dict[str, object],
    public_root: str | None = None,
) -> tuple[Path, Path]:
    decision = evaluate_sn60_promotion(
        king=duel_summary.king,
        candidate=duel_summary.candidate,
        screening_result=screening_result,
    )
    freshness_fingerprint = sn60_freshness_fingerprint(duel_summary)
    record_sn60_benchmark_snapshot(
        lane_id=lane_id,
        sandbox_source=duel_summary.sandbox_source,
        project_keys=list(duel_summary.project_keys),
        public_root=public_root,
    )
    challenge_path = write_challenge_state(
        lane_id,
        ChallengeState(
            schema_version=CHALLENGE_STATE_SCHEMA_VERSION,
            candidate_submission_id=candidate_submission_id,
            candidate_artifact_hash=duel_summary.candidate.artifact_hash,
            king_artifact_hash=duel_summary.king.artifact_hash,
            screening_result=screening_result,
            selected_project_keys=list(duel_summary.project_keys),
            validator_replica_count=1,
            run_ids=[duel_summary.run_id],
            freshness_fingerprint=freshness_fingerprint,
            updated_at=datetime.now(UTC).isoformat(),
        ),
        public_root=public_root,
    )
    promotion_path = write_promotion_record(
        lane_id,
        PromotionRecord(
            schema_version=PROMOTION_RECORD_SCHEMA_VERSION,
            final_metrics=sn60_final_metrics(duel_summary, decision),
            local_replica_scores=sn60_local_replica_scores(duel_summary),
            pass_counts={
                "king": duel_summary.king.codebase_pass_count,
                "candidate": duel_summary.candidate.codebase_pass_count,
            },
            true_positives={
                "king": duel_summary.king.true_positives,
                "candidate": duel_summary.candidate.true_positives,
            },
            invalid_runs={
                "king": duel_summary.king.invalid_runs,
                "candidate": duel_summary.candidate.invalid_runs,
            },
            final_winner=decision.final_winner,
            recorded_at=datetime.now(UTC).isoformat(),
        ),
        public_root=public_root,
    )
    return challenge_path, promotion_path


def sn60_final_metrics(
    duel_summary: Sn60DuelSummary,
    decision: Sn60PromotionDecision,
) -> dict[str, object]:
    king_aggregated = duel_summary.king.aggregated_score
    candidate_aggregated = duel_summary.candidate.aggregated_score
    king_pass_score = sn60_pass_score(duel_summary.king)
    candidate_pass_score = sn60_pass_score(duel_summary.candidate)
    return {
        "run_id": duel_summary.run_id,
        "promotion_ready": decision.promotion_ready,
        "promotion_reason": decision.reason,
        "validator_replica_count": 1,
        "runs_per_project": duel_summary.replicas_per_project,
        "project_pass_threshold": project_pass_threshold_label(duel_summary.replicas_per_project),
        "king_sn60_pass_score": king_pass_score,
        "candidate_sn60_pass_score": candidate_pass_score,
        "candidate_sn60_pass_score_delta": candidate_pass_score - king_pass_score,
        "king_detection_score": king_aggregated,
        "candidate_detection_score": candidate_aggregated,
        "king_aggregated_score": king_aggregated,
        "candidate_aggregated_score": candidate_aggregated,
        "candidate_aggregated_score_delta": candidate_aggregated - king_aggregated,
        "king_true_positives": duel_summary.king.true_positives,
        "candidate_true_positives": duel_summary.candidate.true_positives,
        "king_total_expected": duel_summary.king.total_expected,
        "candidate_total_expected": duel_summary.candidate.total_expected,
        "king_total_found": duel_summary.king.total_found,
        "candidate_total_found": duel_summary.candidate.total_found,
        "king_precision": duel_summary.king.precision,
        "candidate_precision": duel_summary.candidate.precision,
        "king_f1_score": duel_summary.king.f1_score,
        "candidate_f1_score": duel_summary.candidate.f1_score,
        "king_invalid_runs": duel_summary.king.invalid_runs,
        "candidate_invalid_runs": duel_summary.candidate.invalid_runs,
        "sandbox_commit": duel_summary.sandbox_source.sandbox_commit,
        "benchmark_sha256": duel_summary.sandbox_source.benchmark_sha256,
        "scorer_version": duel_summary.sandbox_source.scorer_version,
    }


def sn60_local_replica_scores(duel_summary: Sn60DuelSummary) -> dict[str, list[float]]:
    return {
        "king": [result.score for result in duel_summary.king.replica_results],
        "candidate": [result.score for result in duel_summary.candidate.replica_results],
    }


def record_sn60_benchmark_snapshot(
    *,
    lane_id: str,
    sandbox_source: Sn60SandboxSource,
    project_keys: list[str],
    public_root: str | None = None,
) -> None:
    write_benchmark_snapshot(
        lane_id,
        BenchmarkSnapshotState(
            schema_version=BENCHMARK_SNAPSHOT_SCHEMA_VERSION,
            sandbox_mirror_source=sandbox_source.sandbox_root,
            sandbox_commit_hash=sandbox_source.sandbox_commit,
            benchmark_dataset_id=Path(sandbox_source.benchmark_file).name,
            benchmark_dataset_hash=sandbox_source.benchmark_sha256,
            project_list_hash=sn60_project_list_hash(project_keys),
            project_keys=list(project_keys),
            container_images=[bitsec_project_image(project_key) for project_key in project_keys],
            scorer_version=sandbox_source.scorer_version,
            updated_at=datetime.now(UTC).isoformat(),
        ),
        public_root=public_root,
    )


def sn60_project_list_hash(project_keys: list[str]) -> str:
    payload = json.dumps(sorted(project_keys))
    return sha256(payload.encode("utf-8")).hexdigest()


def sn60_freshness_fingerprint(duel_summary: Sn60DuelSummary) -> str:
    payload = {
        "king_artifact_hash": duel_summary.king.artifact_hash,
        "candidate_artifact_hash": duel_summary.candidate.artifact_hash,
        "project_keys": duel_summary.project_keys,
        "replicas_per_project": duel_summary.replicas_per_project,
        "sandbox_commit": duel_summary.sandbox_source.sandbox_commit,
        "benchmark_sha256": duel_summary.sandbox_source.benchmark_sha256,
        "scorer_version": duel_summary.sandbox_source.scorer_version,
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def sn60_evaluator_version(duel_summary: Sn60DuelSummary) -> str:
    return (
        f"{duel_summary.sandbox_source.scorer_version}"
        f"@{short_hash(duel_summary.sandbox_source.sandbox_commit)}"
    )


def load_challenge_summary(path: str) -> ChallengeSummary:
    payload = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    return ChallengeSummary(
        schema_version=payload["schema_version"],
        run_id=payload["run_id"],
        manifest_path=payload["manifest_path"],
        mode=payload["mode"],
        evaluator_version=payload.get("evaluator_version", ""),
        validator_model=payload.get("validator_model", SN60_VALIDATOR_MODEL),
        king_artifact=payload["king_artifact"],
        candidate_artifact=payload["candidate_artifact"],
        king_artifact_hash=payload.get("king_artifact_hash", ""),
        candidate_artifact_hash=payload.get("candidate_artifact_hash", ""),
        primary_pool_fingerprint=payload.get("primary_pool_fingerprint"),
        created_at=payload["created_at"],
        primary=parse_challenge_pool(payload["primary"]),
        promotion_ready=payload["promotion_ready"],
        promotion_reason=payload["promotion_reason"],
    )


def parse_challenge_pool(payload: dict[str, object]) -> ChallengePoolSummary:
    variant_scores = payload.get("variant_scores") or {}
    variant_detection_scores = payload.get("variant_detection_scores") or {}
    candidate_score = float(variant_scores.get("candidate", 0.0)) if variant_scores else 0.0
    king_score = float(variant_scores.get("king", 0.0)) if variant_scores else 0.0
    return ChallengePoolSummary(
        project_keys=list(payload["project_keys"]),
        run_summary_path=str(payload["run_summary_path"]),
        total_task_weight=float(payload.get("total_task_weight", len(payload["project_keys"]))),
        variant_successes=dict(payload.get("variant_successes") or {}),
        variant_invalid_runs=dict(payload.get("variant_invalid_runs") or {}),
        variant_scores={name: float(score) for name, score in variant_scores.items()},
        variant_detection_scores={
            name: float(score) for name, score in variant_detection_scores.items()
        },
        candidate_beats_king=bool(
            payload.get("candidate_beats_king", candidate_score > king_score)
        ),
        candidate_score_delta=float(
            payload.get("candidate_score_delta", round(candidate_score - king_score, 2))
        ),
        competition_mode=str(payload.get("competition_mode") or "king_duel"),
    )


def write_challenge_summary(path: Path, summary: ChallengeSummary) -> None:
    path.write_text(json.dumps(asdict(summary), indent=2) + "\n", encoding="utf-8")
