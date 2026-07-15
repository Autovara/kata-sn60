"""Per-subnet static screening dispatches through the lane's plugin.

Generic anti-cheat checks stay in the core screener; a lane's plugin adds its own
subnet-specific static findings via ``static_screen``. The plugin is resolved in-process
by ``(pack, mode)`` -- no pack-registry file required. (Phase 2a moved SN60's static rules
out of the unconditional core path and into the SN60 plugin.)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from kata.plugins import (
    EnvSpec,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
    clear_registry,
    register_plugin,
)
from kata.plugins.discovery import load_builtin_plugins
from kata.screening.engine import _plugin_static_screen_findings


class _ScreeningPlugin(SubnetPlugin):
    evaluator_id = "t_eval"
    pack = "t__pack"
    mode = "miner"
    scoring_profile = ScoringProfile.DETERMINISTIC
    validator_identity = "t-v"

    def environment_spec(self) -> EnvSpec:
        return EnvSpec()

    def sample_problems(self, *, seed, config):
        return []

    def benchmark_identity(self, problems) -> str:
        return "b"

    def run_candidate(self, *, agent_path, problems, context):
        return None

    def score(self, raw, problems) -> ScoreCard:
        return ScoreCard(comparable=0.0, passed=True)

    def compare(self, a, b) -> int:
        return 0

    def beats_king(self, candidate, king) -> bool:
        return False

    def static_screen(self, submission_path):
        return ["custom subnet finding"]


@pytest.fixture(autouse=True)
def _restore_registry():
    yield
    clear_registry()
    load_builtin_plugins()


def test_static_screen_dispatches_to_lane_plugin(tmp_path: Path) -> None:
    register_plugin(_ScreeningPlugin())
    findings = _plugin_static_screen_findings(
        submission_root=tmp_path, repo_pack="t__pack", mode="miner"
    )
    assert findings == ["custom subnet finding"]


def test_static_screen_noop_for_unknown_or_missing_lane(tmp_path: Path) -> None:
    # An unregistered pack resolves to no plugin -> no subnet-specific findings.
    assert (
        _plugin_static_screen_findings(
            submission_root=tmp_path, repo_pack="nope__pack", mode="miner"
        )
        == []
    )
    # No repo_pack -> no dispatch at all.
    assert (
        _plugin_static_screen_findings(submission_root=tmp_path, repo_pack=None, mode="miner") == []
    )


def test_sn60_lane_runs_its_static_screen(tmp_path: Path) -> None:
    # Phase 2a: SN60's static rules run via its plugin for the SN60 lane. A bundle with an
    # answer-key token is rejected by SN60's own static_screen through the dispatch.
    (tmp_path / "agent.py").write_text("KNOWN = 'curated-highs-only'\n", encoding="utf-8")
    findings = _plugin_static_screen_findings(
        submission_root=tmp_path, repo_pack="sn60__bitsec", mode="miner"
    )
    assert any(getattr(f, "rule_id", None) == "sn60.answer_key_token" for f in findings)
