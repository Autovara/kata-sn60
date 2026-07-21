from __future__ import annotations

import json
import types
from pathlib import Path

import pytest
from kata.cli import build_parser, main, parse_challenge_candidate

from kata_sn60.cli import sn60_challenge_result_json


def test_sn60_challenge_result_json_preserves_projects_and_execution_screening() -> None:
    variant = types.SimpleNamespace(
        aggregated_score=0.0,
        average_detection_rate=0.0,
        true_positives=0,
        total_expected=0,
        total_found=0,
        precision=0.0,
        f1_score=0.0,
        invalid_runs=1,
        codebase_pass_count=0,
        loose_pass_count=0,
        artifact_hash="hash-23",
        successful_runs=1,
        project_summaries=[],
    )
    screening = {
        "status": "failed",
        "stage": "execution",
        "project_key": "project-alpha",
    }
    result = types.SimpleNamespace(
        run_id="sn60-challenge-test",
        output_root="/tmp/run",
        winner_submission_id=None,
        winner_challenge_summary_path=None,
        promotion_ready=False,
        promotion_reason="no candidate beat the king",
        competition_mode="king_duel",
        king_skipped_reason=None,
        replicas_per_project=1,
        project_keys=["project-alpha"],
        king=None,
        entries=[
            types.SimpleNamespace(
                submission_id="pr-144",
                beats_king=False,
                selected_winner=False,
                duel_run_id="sn60-screening-test",
                screening_result=screening,
                candidate=variant,
            )
        ],
    )

    payload = sn60_challenge_result_json(result)

    assert payload["project_keys"] == ["project-alpha"]
    assert payload["replicas_per_project"] == 1
    assert payload["entries"][0]["screening_result"] == screening


def test_sn60_variant_detail_carries_the_bot_consumed_contract_fields() -> None:
    # The bot keys its running-average ledger on the king's artifact_hash and decides
    # king-bar collapse / per-project infra-failure from successful_runs. These MUST be
    # in the stdout the bot consumes, not only in challenge_result.json. Guards the shape
    # mismatch that silently made continuous scoring inert.
    project = types.SimpleNamespace(
        project_key="project-alpha",
        passed=True,
        successful_runs=3,
        average_detection_rate=0.5,
        true_positives=6,
        total_expected=12,
        total_found=6,
        precision=1.0,
        f1_score=0.5,
    )
    king = types.SimpleNamespace(
        artifact_hash="king-hash-abc",
        aggregated_score=0.5,
        average_detection_rate=0.5,
        true_positives=6,
        total_expected=12,
        total_found=6,
        precision=1.0,
        f1_score=0.5,
        successful_runs=3,
        invalid_runs=0,
        codebase_pass_count=1,
        loose_pass_count=1,
        project_summaries=[project],
    )
    result = types.SimpleNamespace(
        run_id="r",
        output_root="/tmp/r",
        winner_submission_id=None,
        winner_challenge_summary_path=None,
        promotion_ready=False,
        promotion_reason="x",
        competition_mode="king_duel",
        king_skipped_reason=None,
        replicas_per_project=3,
        project_keys=["project-alpha"],
        king=king,
        entries=[],
    )

    payload = sn60_challenge_result_json(result)
    king_json = payload["king"]
    assert king_json["artifact_hash"] == "king-hash-abc"
    assert king_json["successful_runs"] == 3
    assert king_json["projects"][0]["successful_runs"] == 3


def test_top_level_cli_exposes_agent_competition_commands() -> None:
    parser = build_parser()
    subparser_action = next(
        action for action in parser._actions if getattr(action, "choices", None)
    )
    commands = set(subparser_action.choices)

    assert {"king", "submission", "lane", "challenge", "sn60-baseline"} == commands


def test_sn60_baseline_cli_is_separate_from_challenge_mode() -> None:
    parser = build_parser()
    subparser_action = next(
        action for action in parser._actions if getattr(action, "choices", None)
    )
    baseline_parser = subparser_action.choices["sn60-baseline"]
    option_dests = {action.dest for action in baseline_parser._actions if action.option_strings}

    assert "candidate" in option_dests
    assert "king_path" not in option_dests
    assert "candidate_only" not in option_dests


def test_lane_cli_registers_and_lists_packs(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    init_payload = json.loads(capsys.readouterr().out)
    assert init_payload["lane_id"] == "sn60__bitsec"

    assert (
        main(
            [
                "lane",
                "list",
                "--active-only",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    list_payload = json.loads(capsys.readouterr().out)
    assert [pack["lane_id"] for pack in list_payload["packs"]] == ["sn60__bitsec"]
    assert list_payload["packs"][0]["evaluator_id"] == "sn60_bitsec"
    assert list_payload["packs"][0]["active"] is True

    registry_path = tmp_path / "lanes" / "registry.json"
    assert registry_path.exists()

    # Deactivate and confirm active-only listing excludes the lane.
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--inactive",
                "--public-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "lane",
                "list",
                "--active-only",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["packs"] == []


def test_lane_cli_accepts_subnet_pack_alias(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--subnet-pack",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert main(["lane", "list", "--public-root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["packs"][0]["subnet_pack"] == "sn60__bitsec"


def test_lane_cli_sync_registry_rebuilds_from_disk(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    (tmp_path / "lanes" / "registry.json").unlink()

    assert main(["lane", "sync-registry", "--public-root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["packs"] == ["sn60__bitsec"]


def test_challenge_cli_unknown_evaluator_errors() -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "challenge",
                "--evaluator",
                "does-not-exist",
                "--king-path",
                "/k",
                "--candidate",
                "a=/a",
            ]
        )


def test_parse_challenge_candidate_accepts_id_path_pairs() -> None:
    assert parse_challenge_candidate("cand-1=/tmp/agent") == ("cand-1", "/tmp/agent")
    assert parse_challenge_candidate(" cand-2 = /tmp/x ") == ("cand-2", "/tmp/x")


def test_parse_challenge_candidate_rejects_malformed_specs() -> None:
    for bad in ("no-equals", "=only-path", "only-id="):
        with pytest.raises(SystemExit):
            parse_challenge_candidate(bad)


def test_challenge_cli_parses_candidates_and_emits_json(monkeypatch, capsys) -> None:

    fake_result = types.SimpleNamespace(
        run_id="sn60-challenge-x",
        output_root="/tmp/runs/sn60-challenge-x",
        winner_submission_id="cand-b",
        winner_challenge_summary_path="/tmp/runs/sn60-challenge-x/d-1/challenge_summary.json",
        promotion_ready=True,
        promotion_reason="cand-b beat the current SN60 king",
        replicas_per_project=1,
        competition_mode="king_duel",
        king_skipped_reason=None,
        king=types.SimpleNamespace(
            aggregated_score=0.25,
            average_detection_rate=0.25,
            true_positives=1,
            total_expected=4,
            total_found=2,
            precision=0.5,
            f1_score=0.4,
            invalid_runs=0,
            codebase_pass_count=1,
            loose_pass_count=1,
            artifact_hash="hash-257",
            successful_runs=1,
            project_summaries=[],
        ),
        entries=[
            types.SimpleNamespace(
                submission_id="cand-b",
                beats_king=True,
                selected_winner=False,
                duel_run_id="d-1",
                candidate=types.SimpleNamespace(
                    aggregated_score=0.5,
                    average_detection_rate=0.5,
                    true_positives=2,
                    total_expected=4,
                    total_found=3,
                    precision=0.66,
                    f1_score=0.5,
                    invalid_runs=0,
                    codebase_pass_count=2,
                    loose_pass_count=2,
                    artifact_hash="hash-275",
                    successful_runs=1,
                    project_summaries=[],
                ),
            )
        ],
    )
    captured: dict[str, object] = {}

    def fake_run_challenge(self, **kwargs):
        captured.update(kwargs)
        return fake_result

    monkeypatch.setattr("kata_sn60.plugin.Sn60BitsecPlugin.run_challenge", fake_run_challenge)

    exit_code = main(
        [
            "challenge",
            "--evaluator",
            "sn60_bitsec",
            "--king-path",
            "/king",
            "--candidate",
            "cand-b=/c-b",
            "--sn60-project-key",
            "project-alpha",
            "--json",
        ]
    )

    assert exit_code == 0
    assert captured["candidates"] == [("cand-b", "/c-b")]
    assert captured["config"]["project_keys"] == ["project-alpha"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["winner_submission_id"] == "cand-b"
    assert payload["promotion_ready"] is True
    assert payload["entries"][0]["submission_id"] == "cand-b"
    assert payload["entries"][0]["beats_king"] is True
    # Rich per-variant detail for the dashboard's per-PR duel view.
    assert payload["king"]["precision"] == 0.5
    assert "projects" in payload["king"]
    assert payload["entries"][0]["precision"] == 0.66
    assert payload["entries"][0]["f1_score"] == 0.5

def test_challenge_cli_samples_problems_when_keys_omitted(tmp_path, monkeypatch, capsys) -> None:

    benchmark = tmp_path / "sandbox" / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark.parent.mkdir(parents=True)
    keys = [f"proj-{index}" for index in range(5)]
    benchmark.write_text(
        json.dumps([{"project_id": key, "vulnerabilities": [{"title": "x"}]} for key in keys])
        + "\n",
        encoding="utf-8",
    )
    king = tmp_path / "king"
    king.mkdir()
    (king / "agent.py").write_text("def agent_main():\n    return {}\n", encoding="utf-8")

    monkeypatch.delenv("KATA_SN60_PROJECT_KEYS", raising=False)
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "challenge-secret")

    captured: dict[str, object] = {}

    def fake_run_challenge(self, **kwargs):
        captured.update(kwargs)
        return types.SimpleNamespace(
            run_id="r",
            output_root=str(tmp_path / "runs" / "r"),
            winner_submission_id=None,
            winner_challenge_summary_path=None,
            promotion_ready=False,
            promotion_reason="no candidate beat the current SN60 king",
            replicas_per_project=1,
            competition_mode="king_duel",
            king_skipped_reason=None,
            king=types.SimpleNamespace(
                aggregated_score=0.0,
                average_detection_rate=0.0,
                true_positives=0,
                total_expected=0,
                total_found=0,
                precision=0.0,
                f1_score=0.0,
                invalid_runs=0,
                codebase_pass_count=0,
                loose_pass_count=0,
                artifact_hash="hash-428",
                successful_runs=1,
                project_summaries=[],
            ),
            entries=[],
        )

    monkeypatch.setattr("kata_sn60.plugin.Sn60BitsecPlugin.run_challenge", fake_run_challenge)

    exit_code = main(
        [
            "challenge",
            "--evaluator",
            "sn60_bitsec",
            "--king-path",
            str(king),
            "--candidate",
            "cand=/tmp/cand",
            "--sn60-sandbox-root",
            str(tmp_path / "sandbox"),
            "--sn60-benchmark-file",
            str(benchmark),
            "--sn60-sandbox-commit",
            "test-commit",
            "--json",
        ]
    )

    assert exit_code == 0
    # No explicit --sn60-project-key: the CLI passes None and the plugin samples.
    assert captured["config"]["project_keys"] is None
