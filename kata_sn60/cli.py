"""SN60 command-line extensions for challenges, submissions, and proof baselines.

The plugin contributes these commands to the generic ``kata`` CLI without adding
SN60-specific parser or output code to Kata core.
"""

from __future__ import annotations

from pathlib import Path

from kata_sn60.sn60_bitsec import DEFAULT_REPLICAS_PER_PROJECT
from kata_sn60.validator_system import (
    project_pass_threshold_label,
    run_sn60_baseline_only,
    sn60_pass_score,
)


def sn60_add_challenge_arguments(parser) -> None:
    parser.add_argument(
        "--sn60-project-key",
        action="append",
        default=None,
        help=(
            "SN60 project key to score every entrant on. Repeat per project. When "
            "omitted, the challenge secretly samples this challenge's problems from the "
            "benchmark (KATA_SN60_PROJECT_SAMPLE_SIZE / _SECRET)."
        ),
    )
    parser.add_argument("--sn60-replicas-per-project", type=int, default=None)
    parser.add_argument("--sn60-sandbox-root", default=None)
    parser.add_argument("--sn60-benchmark-file", default=None)
    parser.add_argument("--sn60-sandbox-commit", default=None)


def sn60_build_challenge_config(args) -> dict:
    return {
        "sandbox_root": args.sn60_sandbox_root,
        "benchmark_file": args.sn60_benchmark_file,
        "sandbox_commit": args.sn60_sandbox_commit,
        "project_keys": args.sn60_project_key or None,
        "replicas_per_project": args.sn60_replicas_per_project or DEFAULT_REPLICAS_PER_PROJECT,
    }


def sn60_challenge_result_json(result) -> dict:
    runs_per_project = result.replicas_per_project
    return {
        "run_id": result.run_id,
        "challenge_result_path": str(
            (Path(result.output_root) / "challenge_result.json").resolve()
        ),
        "winner_submission_id": result.winner_submission_id,
        "winner_challenge_summary_path": result.winner_challenge_summary_path,
        "promotion_ready": result.promotion_ready,
        "promotion_reason": result.promotion_reason,
        "competition_mode": result.competition_mode,
        "validator_replica_count": 1,
        "project_keys": list(getattr(result, "project_keys", [])),
        "replicas_per_project": result.replicas_per_project,
        "runs_per_project": runs_per_project,
        "project_pass_threshold": project_pass_threshold_label(runs_per_project),
        "king": sn60_variant_detail(result.king) if result.king else None,
        "entries": [
            {
                "submission_id": entry.submission_id,
                "beats_king": entry.beats_king,
                "selected_winner": entry.selected_winner,
                "duel_run_id": entry.duel_run_id,
                "screening_result": getattr(entry, "screening_result", None),
                **sn60_variant_detail(entry.candidate),
            }
            for entry in result.entries
        ],
    }


def sn60_variant_detail(variant) -> dict:
    """Serialize a variant summary (king or candidate) with its per-project
    breakdown so the dashboard can render a detailed per-PR duel view.

    ``artifact_hash`` and ``successful_runs`` (top-level and per-project) are part of
    the consumed contract, not just dashboard detail: the bot keys the king's
    running-average ledger on ``artifact_hash`` and decides whether a variant's king
    bar collapsed / a project infra-failed from ``successful_runs``. They must ride in
    this stdout payload, never only in the ``challenge_result.json`` file.
    """
    return {
        "artifact_hash": variant.artifact_hash,
        "aggregated_score": variant.aggregated_score,
        "detection_score": variant.aggregated_score,
        "sn60_pass_score": sn60_pass_score(variant),
        "average_detection_rate": variant.average_detection_rate,
        "true_positives": variant.true_positives,
        "total_expected": variant.total_expected,
        "total_found": variant.total_found,
        "precision": variant.precision,
        "f1_score": variant.f1_score,
        "successful_runs": variant.successful_runs,
        "invalid_runs": variant.invalid_runs,
        "codebase_pass_count": variant.codebase_pass_count,
        "loose_pass_count": variant.loose_pass_count,
        "projects": [
            {
                "project_key": project.project_key,
                "passed": project.passed,
                "successful_runs": project.successful_runs,
                "detection_rate": project.average_detection_rate,
                "true_positives": project.true_positives,
                "total_expected": project.total_expected,
                "total_found": project.total_found,
                "precision": project.precision,
                "f1_score": project.f1_score,
            }
            for project in variant.project_summaries
        ],
    }


def sn60_render_challenge_text(result) -> str:
    lines = [f"SN60 challenge {result.run_id}"]
    if result.king is not None:
        lines.append(
            f"king pass score {sn60_pass_score(result.king):.3f} "
            f"({result.king.codebase_pass_count}/{len(result.king.project_summaries)} projects, "
            f"detection {result.king.aggregated_score:.3f}, "
            f"tp {result.king.true_positives}/{result.king.total_expected})"
        )
    lines.append("ranking (best first):")
    for position, entry in enumerate(result.entries, start=1):
        if entry.submission_id == result.winner_submission_id:
            marker = "WINNER"
        elif entry.beats_king:
            marker = "beats-king"
        else:
            marker = "-"
        lines.append(
            f"  {position}. {entry.submission_id} "
            f"pass {sn60_pass_score(entry.candidate):.3f} "
            f"({entry.candidate.codebase_pass_count}/"
            f"{len(entry.candidate.project_summaries)} projects, "
            f"detection {entry.candidate.aggregated_score:.3f}, "
            f"tp {entry.candidate.true_positives}) {marker}"
        )
    lines.append(result.promotion_reason)
    return "\n".join(lines)


def register_sn60_cli(subparsers) -> None:
    """Contribute SN60's own subcommands to the `kata` CLI (proof-only baseline)."""
    baseline_cmd = subparsers.add_parser(
        "sn60-baseline",
        help="Score one proof-only SN60 baseline artifact without evaluating the Kata king.",
    )
    baseline_cmd.add_argument(
        "--candidate",
        required=True,
        metavar="ID=PATH",
        help="The baseline artifact as '<submission-id>=<artifact-path>'.",
    )
    baseline_cmd.add_argument(
        "--sn60-project-key",
        action="append",
        required=True,
        help="SN60 project key to score the baseline on. Repeat per project.",
    )
    baseline_cmd.add_argument(
        "--output-root",
        default=None,
        help="Optional base directory for baseline artifacts. Defaults to ./runs.",
    )
    baseline_cmd.add_argument("--sn60-replicas-per-project", type=int, default=None)
    baseline_cmd.add_argument("--sn60-sandbox-root", default=None)
    baseline_cmd.add_argument("--sn60-benchmark-file", default=None)
    baseline_cmd.add_argument("--sn60-sandbox-commit", default=None)
    baseline_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    baseline_cmd.set_defaults(handler=handle_sn60_baseline)


def handle_sn60_baseline(args) -> int:
    from kata.cli import parse_challenge_candidate, print_json

    submission_id, artifact_path = parse_challenge_candidate(args.candidate)
    result = run_sn60_baseline_only(
        submission_id=submission_id,
        artifact_path=artifact_path,
        project_keys=args.sn60_project_key,
        output_root=args.output_root,
        replicas_per_project=args.sn60_replicas_per_project or DEFAULT_REPLICAS_PER_PROJECT,
        sandbox_root=args.sn60_sandbox_root,
        benchmark_file=args.sn60_benchmark_file,
        sandbox_commit=args.sn60_sandbox_commit,
    )
    runs_per_project = result.replicas_per_project
    if args.json:
        print_json(
            {
                "run_id": result.run_id,
                "baseline_summary_path": str(
                    (Path(result.output_root) / "baseline_summary.json").resolve()
                ),
                "competition_mode": result.competition_mode,
                "validator_replica_count": 1,
                "runs_per_project": runs_per_project,
                "project_pass_threshold": project_pass_threshold_label(runs_per_project),
                "project_keys": result.project_keys,
                "replicas_per_project": result.replicas_per_project,
                "sandbox_source": {
                    "sandbox_root": result.sandbox_source.sandbox_root,
                    "benchmark_file": result.sandbox_source.benchmark_file,
                    "benchmark_sha256": result.sandbox_source.benchmark_sha256,
                    "sandbox_commit": result.sandbox_source.sandbox_commit,
                    "scorer_version": result.sandbox_source.scorer_version,
                },
                "entries": [
                    {
                        "submission_id": result.submission_id,
                        "beats_king": None,
                        "selected_winner": False,
                        "duel_run_id": result.run_id,
                        **sn60_variant_detail(result.baseline),
                    }
                ],
            }
        )
    else:
        print(render_sn60_baseline_result(result))
    return 0


def render_sn60_baseline_result(result) -> str:
    lines = [
        f"SN60 baseline replay {result.run_id}",
        "mode: baseline-only proof replay",
        "kata king evaluated: no",
        (
            f"baseline pass score {sn60_pass_score(result.baseline):.3f} "
            f"({result.baseline.codebase_pass_count}/"
            f"{len(result.baseline.project_summaries)} projects, "
            f"detection {result.baseline.aggregated_score:.3f}, "
            f"tp {result.baseline.true_positives}/{result.baseline.total_expected})"
        ),
    ]
    return "\n".join(lines)
