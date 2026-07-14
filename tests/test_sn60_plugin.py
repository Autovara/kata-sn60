"""Phase 2 tests: SN60 wrapped as a SubnetPlugin.

Exercises every plugin method with deterministic hooks (same fixture shape as the
characterization goldens) and confirms the plugin registers on import. The plugin is
pure delegation, so ranking/promotion must match SN60's existing behavior.
"""

from __future__ import annotations

import json
from pathlib import Path

from kata.packages import RunContext, ScoringProfile, get_plugin

from kata_sn60 import SN60_BITSEC_PLUGIN, Sn60BitsecPlugin


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


def _plugin() -> Sn60BitsecPlugin:
    execute, evaluate = _detection_hooks()
    return Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate)


def _score(plugin, *, agent_root, problems, tmp_path, label):
    context = RunContext(
        output_root=str(tmp_path / "runs" / label),
        env=plugin.environment_spec(),
        label=label,
    )
    raw = plugin.run_candidate(agent_path=str(agent_root), problems=problems, context=context)
    return plugin.score(raw, problems)


def test_sn60_plugin_registers_on_import() -> None:
    assert get_plugin("sn60_bitsec") is SN60_BITSEC_PLUGIN


def test_sn60_plugin_identity_and_env() -> None:
    plugin = Sn60BitsecPlugin()
    assert plugin.evaluator_id == "sn60_bitsec"
    assert plugin.pack == "sn60__bitsec"
    assert plugin.mode == "miner"
    assert plugin.scoring_profile is ScoringProfile.DETERMINISTIC
    assert plugin.validator_identity == "sn60-bitsec-sandbox"
    assert plugin.environment_spec().network == "relay_only"


def test_sn60_plugin_sample_problems_and_identity(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    plugin = _plugin()
    problems = plugin.sample_problems(
        seed="round-1",
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-x",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
    )
    assert problems.project_keys == ["project-alpha"]
    assert problems.replicas_per_project == 1
    identity = plugin.benchmark_identity(problems)
    assert identity and identity.endswith(":commit-x:ScaBenchScorerV2")  # non-empty == cacheable


def test_sn60_plugin_scores_rank_and_beat_king_match_engine(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    plugin = _plugin()
    problems = plugin.sample_problems(
        seed="round-1",
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-x",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
    )

    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)  # tp = 1
    king = _score(plugin, agent_root=king_root, problems=problems, tmp_path=tmp_path, label="king")

    cards = {}
    for name, detection in (("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)):
        bundle = tmp_path / name
        _write_detection_bundle(bundle, detection)
        cards[name] = _score(
            plugin, agent_root=bundle, problems=problems, tmp_path=tmp_path, label=name
        )

    # Ranking mirrors sn60_variant_rank: cand-c > cand-b > cand-a (by true positives).
    assert plugin.compare(cards["cand-c"], cards["cand-b"]) > 0
    assert plugin.compare(cards["cand-b"], cards["cand-a"]) > 0
    assert plugin.compare(cards["cand-a"], cards["cand-a"]) == 0

    # beats_king matches evaluate_sn60_promotion: c and b beat the king (tp 3,2 > 1),
    # a does not (tp 0). No king == first promotion always wins.
    assert plugin.beats_king(cards["cand-c"], king) is True
    assert plugin.beats_king(cards["cand-b"], king) is True
    assert plugin.beats_king(cards["cand-a"], king) is False
    # With no king (candidate-only), only a true-positive finder qualifies.
    assert plugin.beats_king(cards["cand-c"], None) is True
    assert plugin.beats_king(cards["cand-a"], None) is False

    # Score card exposes serializable metrics + the native summary in payload.
    assert cards["cand-c"].metrics["true_positives"] == 3
    assert cards["cand-c"].passed is True
    assert cards["cand-c"].payload is not None
