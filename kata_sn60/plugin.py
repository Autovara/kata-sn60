"""SN60 Bitsec implementation of Kata's subnet plugin contract.

The plugin owns every SN60-specific decision—benchmark selection, sealed execution,
scoring, screening, promotion provenance, and CLI extensions—while Kata core remains
subnet-neutral.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from kata.plugins.contract import (
    EnvSpec,
    ProgressUpdate,
    RunContext,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
)

from kata_sn60.execution.policy import tee_execution_enabled
from kata_sn60.king_cache import benchmark_version_key
from kata_sn60.sn60_bitsec import (
    Sn60EvaluationHook,
    Sn60ExecutionHook,
    Sn60ReplicaResult,
    Sn60ReusedExecutionPayloads,
    Sn60SandboxSource,
    Sn60VariantSummary,
    build_cached_variant_hooks,
    build_default_evaluation_hook,
    build_default_execution_hook,
    hash_bundle_root,
    resolve_sn60_sandbox_source,
    score_variant_on_projects,
    summarize_variant,
    validate_sn60_project_keys,
)
from kata_sn60.validator_system.challenge import (
    SN60_MINER_LANE_ID,
    SN60_VALIDATOR_MODEL,
    _apply_running_metrics,
    _sn60_variant_progress,
    evaluate_sn60_promotion,
    sn60_pass_score,
    sn60_variant_rank,
)
from kata_sn60.validator_system.project_selection import resolve_sn60_project_keys

DEFAULT_SCORER_VERSION = "ScaBenchScorerV2"


@dataclass(frozen=True)
class Sn60Problems:
    """SN60's problem set: the sampled projects + the sandbox they run against."""

    project_keys: list[str]
    sandbox_source: Sn60SandboxSource
    replicas_per_project: int
    run_id: str
    challenge_cache_path: str | None = None
    # Durable candidate scoreboard: when set, the candidate's per-project runs are
    # cached the same way as the king's, so an interrupted challenge that resumes
    # during the candidate phase does not re-run (and re-pay for) candidate
    # projects it already scored. Cleared per round by the caller.
    candidate_cache_path: str | None = None
    # One passed execution screener per candidate may be reused as the first
    # scored replica. Entries are created only after the real TEE execution has
    # passed report validation for the current bundle and sampled project.
    screened_execution_payloads: Mapping[str, Sn60ReusedExecutionPayloads] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class Sn60RawRun:
    """One variant's scored replicas, before summarization."""

    variant_name: str
    artifact_root: str
    artifact_hash: str
    replica_results: list[Sn60ReplicaResult]


class Sn60BitsecPlugin(SubnetPlugin):
    """SN60 bitsec (smart-contract vulnerability detection) plugin."""

    evaluator_id = "sn60_bitsec"
    pack = SN60_MINER_LANE_ID  # "sn60__bitsec"
    mode = "miner"
    # SN60 scores come from LLM-driven vulnerability detection plus an LLM judge, so
    # a variant's score drifts run-to-run even on a fixed benchmark. The score is
    # therefore NOISY (score each contender afresh); the king is re-scored every challenge.
    # The benchmark/answer-key is deterministic, but the scoring pipeline is not, so
    # this must never be labelled DETERMINISTIC (which would sanction a persistent,
    # cross-challenge score cache that compares a stale king against fresh candidates).
    scoring_profile = ScoringProfile.NOISY
    validator_identity = SN60_VALIDATOR_MODEL  # "sn60-bitsec-sandbox"

    def __init__(
        self,
        *,
        execution_hook: Sn60ExecutionHook | None = None,
        evaluation_hook: Sn60EvaluationHook | None = None,
        scorer_version: str = DEFAULT_SCORER_VERSION,
    ) -> None:
        # Optional hook injection for tests; production builds the real sandbox
        # (Docker) hooks from the resolved sandbox source at run time.
        self._execution_hook = execution_hook
        self._evaluation_hook = evaluation_hook
        self._scorer_version = scorer_version

    def environment_spec(self) -> EnvSpec:
        # SN60 agents run sealed except for the evaluator's inference gateway.
        # Production is TEE-first so a miner's sealed credential is the only
        # credential available. Local Docker execution is an explicit dev mode.
        return EnvSpec(
            network="relay_only",
            execution="tee" if tee_execution_enabled() else "sandbox",
        )

    def resolve_execution_hook(self, source: Sn60SandboxSource) -> Sn60ExecutionHook:
        """The execution hook (injected in tests, real sandbox in production). The backend is chosen
        by the lane's ``EnvSpec.execution`` (``"tee"`` -> sealed room, else local sandbox)."""
        if self._execution_hook:
            return self._execution_hook
        use_tee = self.environment_spec().execution == "tee"
        return build_default_execution_hook(source, use_tee=use_tee)

    def card_for_summary(self, summary: Sn60VariantSummary) -> ScoreCard:
        """Wrap an already-computed variant summary as a ScoreCard (e.g. a screener
        failure) so it ranks uniformly with scored candidates."""
        return self._score_card(summary)

    def sample_problems(self, *, seed: str, config: dict[str, Any]) -> Sn60Problems:
        sandbox_source = resolve_sn60_sandbox_source(
            sandbox_root=config.get("sandbox_root"),
            benchmark_file=config.get("benchmark_file"),
            sandbox_commit=config.get("sandbox_commit"),
            scorer_version=self._scorer_version,
        )
        project_keys = resolve_sn60_project_keys(
            configured_keys=config.get("project_keys"),
            sandbox_root=config.get("sandbox_root"),
            benchmark_file=config.get("benchmark_file"),
            sandbox_commit=config.get("sandbox_commit"),
        )
        normalized_project_keys = list(project_keys)
        validate_sn60_project_keys(
            normalized_project_keys,
            sandbox_source=sandbox_source,
        )
        replicas_per_project = int(config.get("replicas_per_project", 1))
        if replicas_per_project <= 0:
            raise ValueError("SN60 replicas_per_project must be positive.")
        return Sn60Problems(
            project_keys=normalized_project_keys,
            sandbox_source=sandbox_source,
            replicas_per_project=replicas_per_project,
            run_id=seed,
            challenge_cache_path=config.get("challenge_cache_path"),
            candidate_cache_path=config.get("candidate_challenge_cache_path"),
        )

    def benchmark_identity(self, problems: Sn60Problems) -> str:
        # Deterministic profile: the benchmark is reproducible, so this is a stable,
        # non-empty identity the core can cache the king score by.
        source = problems.sandbox_source
        return f"{source.benchmark_sha256}:{source.sandbox_commit}:{source.scorer_version}"

    def run_candidate(
        self, *, agent_path: str, problems: Sn60Problems, context: RunContext
    ) -> Sn60RawRun:
        source = problems.sandbox_source
        execution_hook = self.resolve_execution_hook(source)
        evaluation_hook = self._evaluation_hook or build_default_evaluation_hook(source)
        artifact_root = Path(agent_path).expanduser().resolve()
        label = context.label
        # The generic label identifies the run dir; the evaluator's variant name stays
        # "king"/"candidate" so execution/evaluation hooks see the same variant as the
        # legacy duel path.
        variant_name = "king" if label == "king" else "candidate"
        # Route the variant through its durable scoreboard when one is configured,
        # so an interrupted challenge resumes cached projects instead of re-running
        # them. The king and candidate use separate scoreboard files, each keyed by
        # its own bundle hash.
        cache_path = (
            problems.challenge_cache_path
            if label == "king"
            else problems.candidate_cache_path
        )
        if cache_path:
            execution_hook, evaluation_hook = build_cached_variant_hooks(
                scoreboard_path=cache_path,
                artifact_hash=hash_bundle_root(artifact_root),
                benchmark_version=benchmark_version_key(
                    source.scorer_version, source.benchmark_sha256
                ),
                base_execution_hook=execution_hook,
                base_evaluation_hook=evaluation_hook,
            )

        reused_execution_payloads = (
            problems.screened_execution_payloads.get(label) if label != "king" else None
        )

        # Emit live per-replica progress through the generic callback, accumulating
        # SN60's running metrics + per-problem breakdown so the board fills in live.
        total = len(problems.project_keys) * problems.replicas_per_project
        acc = {"tp": 0, "expected": 0, "found": 0, "invalid": 0, "projects": []}
        running: dict[str, object] = {}
        done = {"n": 0}

        def _on_replica(_replica_context, replica_result) -> None:
            done["n"] += 1
            _apply_running_metrics(running, acc, replica_result)
            if context.progress is not None:
                context.progress(
                    ProgressUpdate(
                        variant=label,
                        done=done["n"],
                        total=total,
                        state="scoring",
                        metrics=dict(running),
                    )
                )

        replica_results = score_variant_on_projects(
            run_id=f"{problems.run_id}-{label}",
            run_root=Path(context.output_root) / label,
            variant_name=variant_name,
            artifact_root=artifact_root,
            project_keys=problems.project_keys,
            replicas_per_project=problems.replicas_per_project,
            sandbox_source=source,
            execution_hook=execution_hook,
            evaluation_hook=evaluation_hook,
            reused_execution_payloads=reused_execution_payloads,
            progress_callback=_on_replica if context.progress is not None else None,
        )
        return Sn60RawRun(
            variant_name=variant_name,
            artifact_root=str(artifact_root),
            artifact_hash=hash_bundle_root(artifact_root),
            replica_results=replica_results,
        )

    def score(self, raw: Sn60RawRun, problems: Sn60Problems) -> ScoreCard:
        summary = summarize_variant(
            variant_name=raw.variant_name,
            artifact_root=Path(raw.artifact_root),
            artifact_hash=raw.artifact_hash,
            replica_results=raw.replica_results,
        )
        return self._score_card(summary)

    @staticmethod
    def _score_card(summary: Sn60VariantSummary) -> ScoreCard:
        # The native SN60 summary drives compare()/beats_king(); it rides in `payload`
        # (opaque to the core) so `metrics` stays JSON-serializable. `metrics` is the
        # full board snapshot (scores + per-problem breakdown) so the final progress
        # tick fills the dashboard's detail view.
        return ScoreCard(
            comparable=round(sn60_pass_score(summary), 8),
            passed=True,
            metrics=_sn60_variant_progress(summary),
            payload=summary,
        )

    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        rank_a = sn60_variant_rank(a.payload)
        rank_b = sn60_variant_rank(b.payload)
        return (rank_a > rank_b) - (rank_a < rank_b)

    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        if king is None:
            # No king was scored (lazy king): a candidate qualifies as winner only
            # if it found at least one true-positive vulnerability.
            return candidate.payload.true_positives > 0
        decision = evaluate_sn60_promotion(king=king.payload, candidate=candidate.payload)
        return decision.promotion_ready

    def static_screen(self, submission_path: str) -> list | None:
        """SN60 subnet-specific static anti-cheat (benchmark-leak / forbidden tokens).

        Loads the bundle and runs SN60's static rules. Lazy imports avoid a screening
        module-load cycle. Returns findings, or None when the bundle is clean.
        """
        from kata.submissions.bundle import load_bundle_files

        from kata_sn60.static_screening import screen_sn60_static_bundle

        findings = screen_sn60_static_bundle(load_bundle_files(Path(submission_path)))
        return findings or None

    def record_promotion_provenance(
        self, *, entry, verification, summary, public_root: str | None = None
    ) -> None:
        from kata_sn60.promotion import record_sn60_promotion_provenance

        record_sn60_promotion_provenance(
            entry=entry,
            verification=verification,
            summary=summary,
            public_root=public_root,
        )

    def hash_bundle(self, path) -> str:
        return hash_bundle_root(Path(path))

    def benchmark_is_current(self, *, lane_id, summary, public_root=None) -> bool:
        from kata_sn60.verify import sn60_benchmark_is_current

        return sn60_benchmark_is_current(lane_id=lane_id, summary=summary, public_root=public_root)

    def load_challenge_summary(self, path):
        from kata_sn60.validator_system import load_challenge_summary

        return load_challenge_summary(path)

    def benchmark_review(self, bundle_files, *, strict):
        from kata_sn60.screening import sn60_benchmark_review

        return sn60_benchmark_review(bundle_files, strict=strict)

    def llm_review(self, *, submission_root, bundle_files, decision):
        from kata_sn60.llm_review import review_suspicious_submission_with_llm

        return review_suspicious_submission_with_llm(
            submission_root=submission_root,
            bundle_files=bundle_files,
            decision=decision,
        )

    def register_cli(self, subparsers) -> None:
        from kata_sn60.cli import register_sn60_cli

        register_sn60_cli(subparsers)

    def add_challenge_arguments(self, parser) -> None:
        from kata_sn60.cli import sn60_add_challenge_arguments

        sn60_add_challenge_arguments(parser)

    def build_challenge_config(self, args) -> dict:
        from kata_sn60.cli import sn60_build_challenge_config

        return sn60_build_challenge_config(args)

    def challenge_result_json(self, result) -> dict:
        from kata_sn60.cli import sn60_challenge_result_json

        return sn60_challenge_result_json(result)

    def render_challenge_text(self, result) -> str:
        from kata_sn60.cli import sn60_render_challenge_text

        return sn60_render_challenge_text(result)

    def run_challenge(
        self,
        *,
        king_agent_path,
        candidates,
        config,
        output_root,
        run_id=None,
        progress_path=None,
    ):
        # Lazy import avoids the module-load cycle (challenge.py imports this module).
        from .challenge import run_sn60_plugin_challenge

        return run_sn60_plugin_challenge(
            king_artifact_path=king_agent_path,
            candidates=candidates,
            config=config,
            output_root=output_root,
            run_id=run_id,
            plugin=self,
            progress_path=progress_path,
        )
