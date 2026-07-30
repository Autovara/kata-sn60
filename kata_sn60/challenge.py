"""Build SN60 challenge artifacts from a generic ``ChallengeOutcome``.

``run_sn60_plugin_challenge`` runs a full SN60 challenge entirely through the subnet-agnostic
:func:`~kata.core.challenge.run_plugin_challenge` orchestrator and reconstructs the exact
``Sn60ChallengeResult`` (winner challenge summary + challenge_result.json + board progress).
It preserves SN60's optional execution screener and lazy-king behavior, so it is a
drop-in for the legacy ``run_sn60_challenge``.
"""

from __future__ import annotations

import logging
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from kata.core.challenge import ChallengeOutcome, ScoredVariant, run_plugin_challenge

from kata_sn60 import sandbox_snapshot
from kata_sn60.execution.judge_gateway import JudgeGateway, judge_limits_from_env
from kata_sn60.execution.proxy_image import verify_proxy_image
from kata_sn60.execution.scorer_runtime import ScorerRuntime
from kata_sn60.sn60_bitsec import (
    DEFAULT_SANDBOX_PROXY_URL,
    Sn60DuelSummary,
    hash_bundle_root,
    validate_sn60_project_keys,
    write_sn60_duel_summary,
)
from kata_sn60.validator_system.challenge import (
    DEFAULT_SN60_CHALLENGE_SCHEMA_VERSION,
    Sn60ChallengeEntry,
    Sn60ChallengeResult,
    _sn60_variant_progress,
    build_sn60_challenge_id,
    failed_candidate_variant_summary,
    run_optional_sn60_screener_project,
    sn60_duel_to_challenge_summary,
    sn60_variant_rank,
    write_challenge_summary,
    write_sn60_challenge_result,
)
from kata_sn60.validator_system.screening import (
    load_passed_screening_report,
    resolve_sn60_screening_execution_timeout_seconds,
    screening_result_payload,
)

from .challenge_inputs import validate_challenge_candidates
from .plugin import Sn60BitsecPlugin, Sn60Problems
from .progress import Sn60ChallengeProgress

LOGGER = logging.getLogger(__name__)


def _duel_challenge_summary_for(
    outcome: ChallengeOutcome,
    plugin: Sn60BitsecPlugin,
    variant: ScoredVariant,
    *,
    run_id: str,
    output_root: str,
    screening_payloads: dict[str, dict],
) -> str:
    """Write the king-vs-``variant`` duel + challenge summary and return its path."""
    problems: Sn60Problems = outcome.problems
    variant_root = Path(output_root) / variant.label
    duel = Sn60DuelSummary(
        schema_version=DEFAULT_SN60_CHALLENGE_SCHEMA_VERSION,
        run_id=f"{run_id}-{variant.label}",
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(variant_root),
        project_keys=list(problems.project_keys),
        replicas_per_project=problems.replicas_per_project,
        sandbox_source=problems.sandbox_source,
        king=outcome.king.card.payload,
        candidate=variant.card.payload,
    )
    variant_root.mkdir(parents=True, exist_ok=True)
    write_sn60_duel_summary(variant_root / "duel_summary.json", duel)
    summary = sn60_duel_to_challenge_summary(
        duel,
        lane_id=plugin.pack,
        screening_result=screening_payloads.get(variant.label),
    )
    summary_path = variant_root / "challenge_summary.json"
    write_challenge_summary(summary_path, summary)
    return str(summary_path)


def build_sn60_challenge_result(
    outcome: ChallengeOutcome,
    plugin: Sn60BitsecPlugin,
    *,
    run_id: str,
    output_root: str,
    screened_out: list[ScoredVariant] | None = None,
    screening_payloads: dict[str, dict] | None = None,
    screener_run_ids: dict[str, str] | None = None,
    screened_labels: frozenset[str] = frozenset(),
    always_write_candidate_summary: bool = False,
    judge_usage: dict[str, object] | None = None,
    proxy_image: dict[str, object] | None = None,
) -> Sn60ChallengeResult:
    """Reconstruct the SN60 challenge result from a generic outcome and write it.

    ``screened_out`` are candidates that failed the execution screener (never scored);
    they are merged in and ranked with the scored candidates, exactly like the legacy
    path.

    ``always_write_candidate_summary`` (continuous mode) forces the top scored
    candidate's challenge summary to be written even when it did not beat this
    challenge's fresh king -- the promotion decision is then made by the caller from
    the king's running average, so a candidate that clears that average must still
    have a publishable challenge summary regardless of this single duel's outcome.
    """
    screened_out = screened_out or []
    screening_payloads = screening_payloads or {}
    screener_run_ids = screener_run_ids or {}
    problems: Sn60Problems = outcome.problems
    king_card = outcome.king.card if outcome.king is not None else None

    # Rank scored + screener-failed candidates together by the SN60 comparator.
    all_variants = [*outcome.ranked, *screened_out]
    all_variants.sort(key=lambda v: sn60_variant_rank(v.card.payload), reverse=True)

    entries = []
    for variant in all_variants:
        if variant.label in screened_labels:
            beats_king = False
        else:
            beats_king = plugin.beats_king(variant.card, king_card)
        entries.append(
            Sn60ChallengeEntry(
                submission_id=variant.label,
                artifact_path=str(Path(variant.agent_path).expanduser().resolve()),
                artifact_hash=variant.card.payload.artifact_hash,
                beats_king=beats_king,
                duel_run_id=screener_run_ids.get(variant.label) or f"{run_id}-{variant.label}",
                candidate=variant.card.payload,
                selected_winner=(
                    outcome.winner is not None and variant.label == outcome.winner.label
                ),
                screening_result=screening_payloads.get(variant.label),
            )
        )

    winner_challenge_summary_path: str | None = None
    if outcome.winner is not None and outcome.king is not None:
        winner_challenge_summary_path = _duel_challenge_summary_for(
            outcome,
            plugin,
            outcome.winner,
            run_id=run_id,
            output_root=output_root,
            screening_payloads=screening_payloads,
        )
    elif (
        always_write_candidate_summary
        and outcome.king is not None
        and outcome.ranked
    ):
        # Continuous mode with no fresh-duel winner: still publish the top scored
        # candidate's challenge summary so the caller's running-average rule can
        # promote it if it clears the king's average by the margin.
        winner_challenge_summary_path = _duel_challenge_summary_for(
            outcome,
            plugin,
            outcome.ranked[0],
            run_id=run_id,
            output_root=output_root,
            screening_payloads=screening_payloads,
        )

    promotion_reason = (
        f"{outcome.winner.label} beat the current SN60 king"
        if outcome.winner is not None
        else "no candidate beat the current SN60 king"
    )

    result = Sn60ChallengeResult(
        schema_version=DEFAULT_SN60_CHALLENGE_SCHEMA_VERSION,
        run_id=run_id,
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(output_root),
        project_keys=list(problems.project_keys),
        replicas_per_project=problems.replicas_per_project,
        sandbox_source=problems.sandbox_source,
        king=king_card.payload if king_card is not None else None,
        entries=entries,
        winner_submission_id=outcome.winner.label if outcome.winner is not None else None,
        promotion_ready=outcome.winner is not None,
        promotion_reason=promotion_reason,
        winner_challenge_summary_path=winner_challenge_summary_path,
        competition_mode="king_duel",
        judge_usage=judge_usage,
        proxy_image=proxy_image,
    )
    write_sn60_challenge_result(Path(output_root) / "challenge_result.json", result)
    return result


def run_sn60_plugin_challenge(
    *,
    king_artifact_path: str,
    candidates: list[tuple[str, str]],
    config: dict,
    output_root: str,
    run_id: str | None = None,
    plugin: Sn60BitsecPlugin | None = None,
    progress_path: str | None = None,
) -> Sn60ChallengeResult:
    """Run a full SN60 challenge through the generic orchestrator and build its result.

    Screens each candidate (env-gated) before scoring, scores the king lazily (only
    when a candidate qualifies), and writes board-format live progress when
    ``progress_path`` is set.
    """
    candidates = validate_challenge_candidates(candidates)
    plugin = plugin or Sn60BitsecPlugin()
    always_write_candidate_summary = bool(config.get("always_write_candidate_summary"))
    run_id = run_id or build_sn60_challenge_id()
    challenge_root = Path(output_root).expanduser().resolve() / run_id
    challenge_root.mkdir(parents=True, exist_ok=False)

    problems: Sn60Problems = plugin.sample_problems(seed=run_id, config=config)
    validate_sn60_project_keys(
        problems.project_keys,
        sandbox_source=problems.sandbox_source,
    )
    scorer_runtime = None
    if plugin.uses_default_evaluation:
        scorer_runtime = ScorerRuntime.for_challenge(
            source_root=Path(problems.sandbox_source.sandbox_root),
            challenge_root=challenge_root,
        )
        # Prepare before any optional TEE screening spends a miner request. Scoring later invokes
        # this interpreter directly, so concurrent replicas never run uv or race over a shared
        # environment.
        scorer_runtime.prepare()
    writer = (
        Sn60ChallengeProgress(
            run_id=run_id,
            project_keys=problems.project_keys,
            candidate_labels=[label for label, _ in candidates],
            per_variant_total=len(problems.project_keys) * problems.replicas_per_project,
            progress_path=progress_path,
        )
        if progress_path
        else None
    )

    # Optional execution screener: partition candidates before scoring.
    execution_hook = plugin.resolve_execution_hook(problems.sandbox_source)
    qualified: list[tuple[str, str]] = []
    screened_out: list[ScoredVariant] = []
    screening_payloads: dict[str, dict] = {}
    screened_execution_payloads: dict[str, dict[tuple[str, int], dict[str, object]]] = {}
    screener_run_ids: dict[str, str] = {}
    screened_labels: set[str] = set()
    for label, agent_path in candidates:
        # The gate is ONE sealed-room agent run with no intermediate ticks, and it can legitimately
        # take many minutes. Announcing entry and exit -- to the log and to the board -- is what
        # separates "a slow room run is in progress" from "the round has hung", which were
        # previously indistinguishable to anyone watching.
        gate_budget = resolve_sn60_screening_execution_timeout_seconds()
        gate_started = datetime.now(UTC)
        if writer is not None:
            writer.mark_screening(
                label,
                started_at=gate_started.isoformat(),
                timeout_seconds=gate_budget,
            )
        LOGGER.info(
            "[sn60] screening gate: %s entering (budget %.0fs)", label, gate_budget
        )
        try:
            screening = run_optional_sn60_screener_project(
                candidate_artifact_path=agent_path,
                project_keys=problems.project_keys,
                output_root=str(challenge_root / label / "screening"),
                sandbox_source=problems.sandbox_source,
                execution_hook=execution_hook,
            )
        except BaseException:
            LOGGER.warning(
                "[sn60] screening gate: %s did not complete after %.0fs",
                label,
                (datetime.now(UTC) - gate_started).total_seconds(),
            )
            raise
        gate_elapsed = (datetime.now(UTC) - gate_started).total_seconds()
        LOGGER.info(
            "[sn60] screening gate: %s -> %s in %.0fs",
            label,
            "skipped (gate disabled)" if screening is None
            else ("passed" if screening.passed else "FAILED"),
            gate_elapsed,
        )
        if screening is None:
            if writer is not None:
                writer.mark_screening_passed(label, finished_at=datetime.now(UTC).isoformat())
            qualified.append((label, agent_path))
            continue
        payload = screening_result_payload(screening)
        screening_payloads[label] = payload
        if screening.passed:
            if screening.project_key in problems.project_keys:
                # The admission gate has already performed the real sealed execution
                # for this candidate and sampled project. Count that verified work as
                # replica 1 instead of spending a duplicate provider request.
                screened_execution_payloads[label] = {
                    (screening.project_key, 1): load_passed_screening_report(screening)
                }
            if writer is not None:
                writer.mark_screening_passed(label, finished_at=datetime.now(UTC).isoformat())
            qualified.append((label, agent_path))
            continue
        candidate_root = Path(agent_path).expanduser().resolve()
        failed_summary = failed_candidate_variant_summary(
            candidate_artifact_path=str(candidate_root),
            candidate_artifact_hash=hash_bundle_root(candidate_root),
        )
        screened_out.append(
            ScoredVariant(
                label=label,
                agent_path=str(candidate_root),
                card=plugin.card_for_summary(failed_summary),
            )
        )
        screener_run_ids[label] = screening.run_id
        screened_labels.add(label)
        if writer is not None:
            writer.mark_screened_out(
                label,
                screening_result=payload,
                snapshot=_sn60_variant_progress(failed_summary),
            )

    # Lazy king: only score the king when a candidate qualified, so a challenge where
    # everyone is screened out never runs (or reports) the king.
    if writer is not None and qualified:
        writer.mark_scoring_started()
    score_king_effective = bool(qualified)
    scoring_problems = replace(problems, screened_execution_payloads=screened_execution_payloads)

    # The judge budget is per CHALLENGE, so one gateway spans the whole scoring phase -- king and
    # every candidate -- rather than one per project. Its caps then bound what this duel can spend
    # on the LLM judge no matter how many projects, replicas or findings it turns out to involve.
    judge_limits = judge_limits_from_env()
    # BEFORE any paid scoring: the judge's answers come from the proxy container, so an
    # unattributable proxy makes every score in this challenge unattributable too. Checked once per
    # challenge rather than per replica -- a container cannot change underneath a running duel
    # without the round failing anyway -- and recorded either way so an unpinned deployment is
    # visible in the published result instead of only in an operator's memory.
    proxy_provenance = verify_proxy_image(
        expected_sandbox_commit=problems.sandbox_source.sandbox_commit,
        expected_tree_sha256=sandbox_snapshot.tree_sha256_for(
            Path(problems.sandbox_source.sandbox_root)
        ),
    ).as_dict()
    with ExitStack() as stack:
        judge_gateway = None
        if scorer_runtime is not None:
            stack.enter_context(scorer_runtime)
        if judge_limits is not None:
            judge_gateway = stack.enter_context(
                JudgeGateway(upstream_url=DEFAULT_SANDBOX_PROXY_URL, limits=judge_limits)
            )
        plugin.set_active_scorer_runtime(scorer_runtime)
        plugin.set_active_judge_gateway(judge_gateway)
        try:
            outcome = run_plugin_challenge(
                plugin,
                king_agent_path=king_artifact_path,
                candidates=qualified,
                config=config,
                output_root=str(challenge_root),
                seed=run_id,
                score_king=score_king_effective,
                progress=writer.on_update if writer is not None else None,
                problems=scoring_problems,
            )
        finally:
            plugin.set_active_judge_gateway(None)
            plugin.set_active_scorer_runtime(None)
        # Read the meter INSIDE the gateway's lifetime: it is the settled truth for what this
        # challenge spent, and the caller settles the day budget from it.
        judge_usage = (
            judge_gateway.final_usage().as_dict() if judge_gateway is not None else None
        )

    if writer is not None:
        writer.finalize(outcome, plugin)

    return build_sn60_challenge_result(
        outcome,
        plugin,
        run_id=run_id,
        output_root=str(challenge_root),
        screened_out=screened_out,
        screening_payloads=screening_payloads,
        screener_run_ids=screener_run_ids,
        screened_labels=frozenset(screened_labels),
        always_write_candidate_summary=always_write_candidate_summary,
        judge_usage=judge_usage,
        proxy_image=proxy_provenance,
    )
