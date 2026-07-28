"""Proof-only SN60 public-baseline comparison: build and render a side-by-side
report of the latest Kata challenge result versus the public SN60 baseline agent.

This is evidence-only tooling: the baseline is never eligible for promotion and
does not affect the challenge winner.

Moved here from ``kata-bot``. Which metrics a baseline comparison shows, what reads as a
regression, and how the report is worded are all SN60 domain knowledge; the shared resident holds
none of it. It asks the plugin over the engine subprocess seam (``kata sn60-baseline-compare``)
and writes back what it is handed.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

LOGGER = logging.getLogger("kata_sn60.baseline_report")

#: The competition mode a baseline report labels its Kata side with. Duplicated from the platform
#: rather than imported: the plugin must not depend on kata-bot, and one string is a smaller cost
#: than that dependency.
DEFAULT_COMPETITION_MODE = "king_duel"


def _safe_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
SN60_EXECUTION_TIMEOUT_ENV = "KATA_SN60_EXECUTION_TIMEOUT_SECONDS"
MIN_SN60_BASELINE_EXECUTION_TIMEOUT_SECONDS = 35 * 60


def load_sn60_baseline_manifest(baseline_path: Path) -> dict[str, object]:
    manifest_path = baseline_path / "manifest.json"
    if not manifest_path.exists():
        return {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("Failed to read SN60 baseline manifest: %s", manifest_path)
        return {}
    return payload if isinstance(payload, dict) else {}


def sn60_baseline_env_overrides() -> dict[str, str]:
    """Keep proof-only SN60 baseline runs out of Kata-only gates and long enough
    for Bitsec's sandbox wrapper to collect large queued results.
    """
    timeout_value = os.environ.get(SN60_EXECUTION_TIMEOUT_ENV, "").strip()
    try:
        timeout_seconds = float(timeout_value) if timeout_value else 0.0
    except ValueError:
        timeout_seconds = 0.0
    safe_timeout = max(
        timeout_seconds,
        float(MIN_SN60_BASELINE_EXECUTION_TIMEOUT_SECONDS),
    )
    return {
        "KATA_SN60_ENABLE_SCREENER_PROJECT": "false",
        SN60_EXECUTION_TIMEOUT_ENV: str(int(safe_timeout)),
    }


def sn60_metric(summary: dict[str, object], name: str) -> object:
    value = summary.get(name)
    if value is None and name == "sn60_pass_score":
        projects = summary.get("project_summaries")
        if isinstance(projects, list) and projects:
            try:
                passed = sum(
                    1
                    for item in projects
                    if isinstance(item, dict) and bool(item.get("passed"))
                )
                return passed / len(projects)
            except ZeroDivisionError:
                return None
    return value


def sn60_variant_from_entry(entry: dict[str, object]) -> dict[str, object]:
    candidate = entry.get("candidate")
    return candidate if isinstance(candidate, dict) else entry


def _percent(value: object) -> str:
    numeric = _safe_float(value)
    return "n/a" if numeric is None else f"{numeric * 100:.2f}%"


def _plain(value: object) -> str:
    return "n/a" if value is None else str(value)


def _metric_row(label: str, summary: dict[str, object]) -> dict[str, object]:
    pass_score = sn60_metric(summary, "sn60_pass_score")
    if pass_score is None:
        pass_score = sn60_metric(summary, "aggregated_score")
    return {
        "label": label,
        "pass_score": pass_score,
        "detection_score": sn60_metric(summary, "aggregated_score"),
        "true_positives": sn60_metric(summary, "true_positives"),
        "total_expected": sn60_metric(summary, "total_expected"),
        "total_found": sn60_metric(summary, "total_found"),
        "precision": sn60_metric(summary, "precision"),
        "f1_score": sn60_metric(summary, "f1_score"),
        "invalid_runs": sn60_metric(summary, "invalid_runs"),
        "codebase_pass_count": sn60_metric(summary, "codebase_pass_count"),
        "successful_runs": sn60_metric(summary, "successful_runs"),
    }


def _entry_for_submission(
    entries: list[dict[str, object]], submission_id: str
) -> dict[str, object]:
    for entry in entries:
        if entry.get("submission_id") == submission_id:
            return entry
    return {}


def _winner_details_from_status(
    status: dict[str, object], submission_id: str
) -> dict[str, object]:
    for entrant in status.get("entrants") or []:
        if not isinstance(entrant, dict):
            continue
        if entrant.get("submission_id") == submission_id:
            return {
                "submission_id": submission_id,
                "pull_number": entrant.get("pull_number"),
                "author": entrant.get("author"),
                "status": entrant.get("status"),
            }
    return {"submission_id": submission_id}


def build_sn60_baseline_comparison(
    *,
    source_challenge: dict[str, object],
    baseline: dict[str, object],
) -> dict[str, object]:
    status = source_challenge.get("_challenge_status")
    status = status if isinstance(status, dict) else {}
    entries = [
        entry for entry in source_challenge.get("entries") or [] if isinstance(entry, dict)
    ]
    winner_submission_id = str(source_challenge.get("winner_submission_id") or "").strip()
    reference_label = "Current Kata king"
    reference_details: dict[str, object] = {"source": "king"}
    reference_summary = source_challenge.get("king")
    if winner_submission_id:
        winner_entry = _entry_for_submission(entries, winner_submission_id)
        if winner_entry:
            reference_summary = sn60_variant_from_entry(winner_entry)
            reference_label = f"Kata challenge winner ({winner_submission_id})"
            reference_details = {
                "source": "challenge_winner",
                **_winner_details_from_status(status, winner_submission_id),
            }
    reference_summary = reference_summary if isinstance(reference_summary, dict) else {}

    baseline_entry = baseline.get("entry")
    baseline_entry = baseline_entry if isinstance(baseline_entry, dict) else {}
    baseline_summary = sn60_variant_from_entry(baseline_entry)
    manifest = baseline.get("artifact_manifest")
    manifest = manifest if isinstance(manifest, dict) else {}
    sandbox_source = source_challenge.get("sandbox_source")
    sandbox_source = sandbox_source if isinstance(sandbox_source, dict) else {}
    project_keys = [
        str(item)
        for item in (
            source_challenge.get("project_keys") or baseline.get("project_keys") or []
        )
        if str(item).strip()
    ]
    return {
        "schema_version": 1,
        "source_challenge_run_id": source_challenge.get("run_id"),
        "baseline_run_id": baseline.get("run_id"),
        "status": baseline.get("status"),
        "reference": {
            "label": reference_label,
            "details": reference_details,
            "metrics": _metric_row(reference_label, reference_summary),
        },
        "baseline": {
            "label": "SN60 public baseline",
            "submission_id": baseline.get("submission_id"),
            "artifact_path": baseline.get("artifact_path"),
            "manifest": manifest,
            "metrics": _metric_row("SN60 public baseline", baseline_summary),
            "beats_reference": baseline.get("beats_king"),
        },
        "conditions": {
            "project_keys": project_keys,
            "project_count": len(project_keys),
            "replicas_per_project": source_challenge.get("replicas_per_project")
            or source_challenge.get("runs_per_project")
            or baseline.get("replicas_per_project"),
            "project_pass_threshold": source_challenge.get("project_pass_threshold"),
            "competition_mode": source_challenge.get("competition_mode")
            or DEFAULT_COMPETITION_MODE,
            "inference": {
                "credential_owner": "miner",
                "cost_owner": "miner",
                "credential_visibility": "tee-only",
                "provider_selection": "miner-selected_from_operator_allowlist",
                "model_selection": "agent-controlled",
                "sampling_selection": "agent-controlled",
                "validator_inference_limits": "none",
            },
            "sandbox_source": sandbox_source,
            "baseline_timeout_seconds": sn60_baseline_env_overrides().get(
                SN60_EXECUTION_TIMEOUT_ENV
            ),
            "reference_metrics_source": "saved_latest_challenge_result",
            "baseline_evaluation_mode": "baseline_only_candidate_replay",
        },
    }


def render_sn60_baseline_comparison_markdown(
    comparison: dict[str, object],
) -> str:
    conditions = comparison.get("conditions")
    conditions = conditions if isinstance(conditions, dict) else {}
    reference = comparison.get("reference")
    reference = reference if isinstance(reference, dict) else {}
    baseline = comparison.get("baseline")
    baseline = baseline if isinstance(baseline, dict) else {}
    ref_metrics = reference.get("metrics")
    ref_metrics = ref_metrics if isinstance(ref_metrics, dict) else {}
    base_metrics = baseline.get("metrics")
    base_metrics = base_metrics if isinstance(base_metrics, dict) else {}
    manifest = baseline.get("manifest")
    manifest = manifest if isinstance(manifest, dict) else {}
    sandbox_source = conditions.get("sandbox_source")
    sandbox_source = sandbox_source if isinstance(sandbox_source, dict) else {}
    project_keys = [str(item) for item in conditions.get("project_keys") or []]
    source_urls = manifest.get("source_urls")
    source_urls = source_urls if isinstance(source_urls, dict) else {}

    def metric_line(name: str, key: str, *, percent: bool = False) -> str:
        left = ref_metrics.get(key)
        right = base_metrics.get(key)
        left_text = _percent(left) if percent else _plain(left)
        right_text = _percent(right) if percent else _plain(right)
        return f"| {name} | {left_text} | {right_text} |"

    lines = [
        "# Kata vs SN60 Baseline Comparison",
        "",
        f"- Source challenge: `{comparison.get('source_challenge_run_id') or 'unknown'}`",
        f"- Baseline run: `{comparison.get('baseline_run_id') or 'unknown'}`",
        f"- Status: **{comparison.get('status') or 'unknown'}**",
        "",
        "## Compared Agents",
        "",
        f"- Kata reference: **{reference.get('label') or 'Kata agent'}**",
        f"- SN60 baseline: "
        f"**{manifest.get('baseline_id') or baseline.get('submission_id') or 'sn60-baseline'}**",
        f"- SN60 source: `{manifest.get('source') or 'unknown'}`",
        f"- SN60 agent id/version: `{manifest.get('agent_id') or 'unknown'}`"
        f" / `{manifest.get('agent_version') or 'unknown'}`",
        f"- SN60 project set: `{manifest.get('project_set_name') or 'unknown'}`",
        f"- SN60 code sha256: `{manifest.get('code_sha256') or 'unknown'}`",
    ]
    if source_urls:
        lines.extend(
            [
                f"- SN60 detail URL: {source_urls.get('detail') or 'n/a'}",
                f"- SN60 scores URL: {source_urls.get('scores') or 'n/a'}",
            ]
        )
    lines.extend(
        [
            "",
            "## Matched Evaluation Conditions",
            "",
            f"- Projects: **{conditions.get('project_count') or len(project_keys)}**",
            f"- Replicas per project: **{conditions.get('replicas_per_project') or 'n/a'}**",
            f"- Project pass rule: **{conditions.get('project_pass_threshold') or 'n/a'}**",
            "- Inference credentials and provider charges: **owned by each miner**",
            "- Model and sampling: **chosen by each agent**",
            "- Validator inference caps: **none; model, token, call, and retry choices are"
            " not capped by Kata**",
            "- Network boundary: **agents use the in-room inference gateway with their"
            " sealed miner credential**",
            "- Kata reference metrics: **reused from the saved completed challenge; the Kata"
            " king/winner is not re-evaluated by this baseline replay**",
            "- SN60 baseline mode: **baseline-only candidate replay**",
            f"- Sandbox commit: `{sandbox_source.get('sandbox_commit') or 'unknown'}`",
            f"- Benchmark sha256: `{sandbox_source.get('benchmark_sha256') or 'unknown'}`",
            f"- Scorer: `{sandbox_source.get('scorer_version') or 'unknown'}`",
            "",
            "## Results",
            "",
            f"| Metric | {reference.get('label') or 'Kata reference'} | SN60 baseline |",
            "| --- | ---: | ---: |",
            metric_line("Project/codebase pass score", "pass_score", percent=True),
            metric_line("Detection score", "detection_score", percent=True),
            metric_line("Codebase passes", "codebase_pass_count"),
            metric_line("True positives", "true_positives"),
            metric_line("Total expected", "total_expected"),
            metric_line("Total findings returned", "total_found"),
            metric_line("Precision", "precision", percent=True),
            metric_line("F1 score", "f1_score", percent=True),
            metric_line("Invalid runs", "invalid_runs"),
            metric_line("Successful runs", "successful_runs"),
            "",
            "## Selected Projects",
            "",
        ]
    )
    lines.extend(f"- `{key}`" for key in project_keys)
    lines.extend(
        [
            "",
            "## Plain-English Summary",
            "",
            "This comparison replays only the public SN60 baseline against the same project"
            " set used by the latest Kata challenge.",
            "The Kata reference numbers come from the already-completed challenge summary, so"
            " this command does not spend tokens re-running the Kata king or winner.",
            "The SN60 baseline is proof-only: it is not eligible for Kata promotion and does"
            " not affect the challenge winner.",
            "Use this report as evidence for the matched evaluation conditions and the"
            " side-by-side result, not as a claim about every possible future challenge.",
            "",
        ]
    )
    return "\n".join(lines)
