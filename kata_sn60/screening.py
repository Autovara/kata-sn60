"""SN60 benchmark-replay screening (anti-memorization): flag/reject copied benchmark answers.

Called by the generic screener via the plugin's ``benchmark_review`` seam so
``screening_system/engine.py`` stays subnet-blind. Relocates to ``kata-sn60`` in Phase 3.
"""

from __future__ import annotations

from dataclasses import replace

from kata.screening_system.models import ScreeningFinding

from kata_sn60.benchmark_replay import (
    analyze_benchmark_replay,
    is_concrete_replay_finding,
)


def sn60_benchmark_review(
    bundle_files: dict[str, str], *, strict: bool
) -> tuple[list[ScreeningFinding], list[ScreeningFinding], float]:
    """SN60 benchmark-replay analysis -> (reject_findings, review_findings, score).

    In strict mode, concrete replay evidence is promoted from review to reject.
    """
    review_findings, score = analyze_benchmark_replay(bundle_files)
    reject_findings: list[ScreeningFinding] = []
    if strict:
        concrete = [f for f in review_findings if is_concrete_replay_finding(f)]
        reject_findings = _promote_replay_findings(concrete)
        review_findings = [
            f for f in review_findings if not is_concrete_replay_finding(f)
        ]
    return reject_findings, review_findings, score


def _promote_replay_findings(findings: list[ScreeningFinding]) -> list[ScreeningFinding]:
    return [
        replace(finding, severity="reject", reason=_render_replay_rejection_reason(finding))
        for finding in findings
    ]


def _render_replay_rejection_reason(finding: ScreeningFinding) -> str:
    detail = finding.reason.strip()
    if detail.startswith("SN60 screening found "):
        detail = detail.removeprefix("SN60 screening found ").strip()
    if detail.startswith("SN60 screening "):
        detail = detail.removeprefix("SN60 screening ").strip()
    if not detail:
        detail = (
            "concrete benchmark-specific replay evidence was found "
            f"by `{finding.rule_id}`."
        )
    return (
        "SN60 screening rejected hardcoded benchmark replay: "
        f"{detail} Remove benchmark IDs, known finding IDs, copied finding "
        "titles/answers, and any prewritten benchmark-specific reports."
    )
