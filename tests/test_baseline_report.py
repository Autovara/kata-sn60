"""The SN60 baseline comparison and its operator report.

Moved here from ``kata-bot``. Which metrics a baseline comparison shows, what reads as a regression,
and how the report is worded are SN60 domain knowledge, so they are defined and tested here. The
resident's side — that it asks over the subprocess seam and publishes what it is handed, unaltered —
is tested in ``kata-bot``.

The report is operator-facing evidence, so these tests assert its *content*, not merely that a
string was produced: a report that silently stopped naming the project set or the inference
ownership would still render, and would still be useless as evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60.baseline_report import (
    build_sn60_baseline_comparison,
    load_sn60_baseline_manifest,
    render_sn60_baseline_comparison_markdown,
    sn60_baseline_env_overrides,
)

CHALLENGE = {
    "run_id": "challenge-main",
    "winner_submission_id": "pr-9",
    "project_keys": ["proj-a", "proj-b"],
    "competition_mode": "king_duel",
    "runs_per_project": 3,
    "entries": [
        {
            "submission_id": "pr-9",
            "candidate": {"sn60_pass_score": 0.8, "aggregated_score": 0.77, "true_positives": 4,
                          "total_expected": 5, "total_found": 4, "precision": 0.9,
                          "f1_score": 0.85, "invalid_runs": 0, "codebase_pass_count": 2,
                          "successful_runs": 6},
        }
    ],
    "_challenge_status": {
        "entrants": [
            {"submission_id": "pr-9", "pull_number": 9, "author": "miner-one", "status": "scored"}
        ]
    },
}

BASELINE = {
    "run_id": "challenge-baseline",
    "status": "completed",
    "submission_id": "sn60-baseline",
    "beats_king": False,
    "artifact_manifest": {"agent_id": 1611, "baseline_id": "sn60-v3.1.3-agent-1611",
                          "source": "github.com/example/sn60-baseline", "agent_version": "3.1.3"},
    "entry": {
        "submission_id": "sn60-baseline",
        "sn60_pass_score": 0.5, "aggregated_score": 0.48, "true_positives": 2,
        "total_expected": 5, "total_found": 3, "precision": 0.6, "f1_score": 0.55,
        "invalid_runs": 1, "codebase_pass_count": 1, "successful_runs": 5,
    },
}


@pytest.fixture
def comparison() -> dict:
    return build_sn60_baseline_comparison(source_challenge=CHALLENGE, baseline=BASELINE)


# ---- the comparison ------------------------------------------------------------------------------

def test_the_kata_side_comes_from_the_recorded_winner(comparison) -> None:
    """The Kata numbers are REUSED from the completed challenge, never re-run: re-evaluating the
    king for a proof-only report would spend real tokens for evidence nobody promotes on."""
    assert comparison["reference"]["details"] == {
        "source": "challenge_winner",
        "submission_id": "pr-9",
        "pull_number": 9,
        "author": "miner-one",
        "status": "scored",
    }


def test_without_a_recorded_winner_it_falls_back_to_the_king() -> None:
    """A challenge that promoted nobody still has a king worth comparing against."""
    built = build_sn60_baseline_comparison(
        source_challenge={k: v for k, v in CHALLENGE.items() if k != "winner_submission_id"},
        baseline=BASELINE,
    )
    assert built["reference"]["details"] == {"source": "king"}


def test_both_sides_carry_the_full_sn60_metric_row(comparison) -> None:
    """The metric set IS the comparison. Dropping one silently narrows the evidence, and the report
    would still render it as `n/a` rather than fail."""
    for side, expected in (
        ("reference", {"pass_score": 0.8, "detection_score": 0.77, "true_positives": 4,
                       "total_expected": 5, "total_found": 4, "precision": 0.9, "f1_score": 0.85,
                       "invalid_runs": 0, "codebase_pass_count": 2, "successful_runs": 6}),
        ("baseline", {"pass_score": 0.5, "detection_score": 0.48, "true_positives": 2,
                      "total_expected": 5, "total_found": 3, "precision": 0.6, "f1_score": 0.55,
                      "invalid_runs": 1, "codebase_pass_count": 1, "successful_runs": 5}),
    ):
        metrics = dict(comparison[side]["metrics"])
        metrics.pop("label")
        assert metrics == expected, side


def test_a_missing_pass_score_falls_back_to_the_detection_score() -> None:
    """Older result documents predate `sn60_pass_score`; the report must still show a headline
    number rather than `n/a` for the side that happens to be older."""
    entry = {"submission_id": "pr-9", "candidate": {"aggregated_score": 0.42}}
    built = build_sn60_baseline_comparison(
        source_challenge={**CHALLENGE, "entries": [entry]}, baseline=BASELINE
    )
    assert built["reference"]["metrics"]["pass_score"] == 0.42


def test_pass_score_can_be_derived_from_the_per_project_verdicts() -> None:
    """SN60 passes a codebase or does not; when only the per-project verdicts survive, the pass
    score is the fraction that passed."""
    entry = {"submission_id": "pr-9", "candidate": {"project_summaries": [
        {"passed": True}, {"passed": True}, {"passed": False}, {"passed": False}]}}
    built = build_sn60_baseline_comparison(
        source_challenge={**CHALLENGE, "entries": [entry]}, baseline=BASELINE
    )
    assert built["reference"]["metrics"]["pass_score"] == 0.5


def test_the_report_shows_both_sides_numbers(comparison) -> None:
    report = render_sn60_baseline_comparison_markdown(comparison)
    assert "80.00%" in report and "50.00%" in report


def test_it_records_the_project_set_both_sides_faced(comparison) -> None:
    """Without this the report compares two agents on unstated, possibly different work."""
    assert comparison["conditions"]["project_keys"] == ["proj-a", "proj-b"]


def test_it_records_who_owned_and_paid_for_inference(comparison) -> None:
    """The evidence the report exists to give: the validator funded none of this."""
    assert comparison["conditions"]["inference"] == {
        "credential_owner": "miner",
        "cost_owner": "miner",
        "credential_visibility": "tee-only",
        "provider_selection": "miner-selected_from_operator_allowlist",
        "model_selection": "agent-controlled",
        "sampling_selection": "agent-controlled",
        "validator_inference_limits": "none",
    }


def test_a_missing_challenge_entry_does_not_crash_the_report() -> None:
    """A baseline run is proof-only; a thin challenge document must degrade, not raise."""
    built = build_sn60_baseline_comparison(source_challenge={}, baseline={})
    assert isinstance(built, dict)
    assert render_sn60_baseline_comparison_markdown(built)


# ---- the rendered report -------------------------------------------------------------------------

def test_the_report_names_the_baseline_it_replayed(comparison) -> None:
    assert "sn60-v3.1.3-agent-1611" in render_sn60_baseline_comparison_markdown(comparison)


def test_the_report_names_the_project_set(comparison) -> None:
    report = render_sn60_baseline_comparison_markdown(comparison)
    assert "`proj-a`" in report and "`proj-b`" in report


def test_the_report_states_the_cost_and_capping_facts(comparison) -> None:
    """These sentences ARE the evidence. A report that dropped them would still render."""
    report = render_sn60_baseline_comparison_markdown(comparison)
    assert "# Kata vs SN60 Baseline Comparison" in report
    assert "owned by each miner" in report
    assert "chosen by each agent" in report
    assert "model, token, call, and retry choices are not capped by Kata" in report
    assert "does not spend tokens re-running the Kata king or winner" in report


def test_the_report_states_it_is_proof_only(comparison) -> None:
    """A reader must not mistake this for a promotion decision."""
    report = render_sn60_baseline_comparison_markdown(comparison)
    assert "not eligible for Kata promotion" in report


# ---- the env a proof-only run needs ---------------------------------------------------------

def test_the_screener_is_off_for_a_proof_only_run() -> None:
    assert sn60_baseline_env_overrides()["KATA_SN60_ENABLE_SCREENER_PROJECT"] == "false"


def test_the_execution_timeout_has_a_floor(monkeypatch) -> None:
    """Bitsec's sandbox wrapper collects large queued results; a short deployment timeout would
    truncate a baseline run and make the comparison look like a regression."""
    monkeypatch.setenv("KATA_SN60_EXECUTION_TIMEOUT_SECONDS", "420")
    assert sn60_baseline_env_overrides()["KATA_SN60_EXECUTION_TIMEOUT_SECONDS"] == "2100"


def test_a_longer_configured_timeout_is_kept(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_EXECUTION_TIMEOUT_SECONDS", "5000")
    assert sn60_baseline_env_overrides()["KATA_SN60_EXECUTION_TIMEOUT_SECONDS"] == "5000"


@pytest.mark.parametrize("value", ["", "not-a-number"])
def test_an_unusable_timeout_falls_back_to_the_floor(monkeypatch, value) -> None:
    monkeypatch.setenv("KATA_SN60_EXECUTION_TIMEOUT_SECONDS", value)
    assert sn60_baseline_env_overrides()["KATA_SN60_EXECUTION_TIMEOUT_SECONDS"] == "2100"


# ---- the manifest --------------------------------------------------------------------------------

def test_a_missing_manifest_is_empty_not_an_error(tmp_path: Path) -> None:
    assert load_sn60_baseline_manifest(tmp_path) == {}


def test_a_corrupt_manifest_is_empty_not_an_error(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text("{ not json", encoding="utf-8")
    assert load_sn60_baseline_manifest(tmp_path) == {}


def test_a_valid_manifest_is_read(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(json.dumps({"agent_id": 1611}), encoding="utf-8")
    assert load_sn60_baseline_manifest(tmp_path)["agent_id"] == 1611


# ---- the subcommands the resident calls -----------------------------------------------------

def test_the_plugin_registers_the_commands_the_resident_uses() -> None:
    """The resident invokes these by name over the engine subprocess seam. A rename here is a
    silently broken baseline report, so the names are pinned."""
    import argparse

    from kata_sn60.cli import register_sn60_cli

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    register_sn60_cli(subparsers)
    for name in ("sn60-baseline", "sn60-baseline-compare", "sn60-baseline-env"):
        assert name in subparsers.choices, name


def test_the_compare_command_emits_both_documents(tmp_path, capsys) -> None:
    import argparse

    from kata_sn60.cli import handle_sn60_baseline_compare

    challenge = tmp_path / "c.json"
    baseline = tmp_path / "b.json"
    challenge.write_text(json.dumps(CHALLENGE), encoding="utf-8")
    baseline.write_text(json.dumps(BASELINE), encoding="utf-8")

    code = handle_sn60_baseline_compare(argparse.Namespace(
        challenge_result=str(challenge), baseline_result=str(baseline),
        challenge_status=None, json=True))

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["comparison"]["conditions"]["project_keys"] == ["proj-a", "proj-b"]
    assert "# Kata vs SN60 Baseline Comparison" in payload["report_markdown"]


def test_the_compare_command_degrades_on_unreadable_input(tmp_path, capsys) -> None:
    """A completed baseline run cost real time. An unreadable document must not lose it."""
    import argparse

    from kata_sn60.cli import handle_sn60_baseline_compare

    assert handle_sn60_baseline_compare(argparse.Namespace(
        challenge_result=str(tmp_path / "missing.json"),
        baseline_result=str(tmp_path / "gone.json"),
        challenge_status=None, json=True)) == 0
    assert json.loads(capsys.readouterr().out)["report_markdown"]


def test_the_env_command_emits_the_overrides(capsys) -> None:
    import argparse

    from kata_sn60.cli import handle_sn60_baseline_env

    assert handle_sn60_baseline_env(argparse.Namespace(json=True)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["env_overrides"]["KATA_SN60_ENABLE_SCREENER_PROJECT"] == "false"


def test_the_report_module_does_not_import_kata_bot() -> None:
    """The plugin must not depend on the resident: it runs in the engine subprocess, which does not
    have kata-bot installed at all."""
    source = (Path(__file__).resolve().parent.parent
              / "kata_sn60" / "baseline_report.py").read_text(encoding="utf-8")
    assert "kata_bot" not in source
