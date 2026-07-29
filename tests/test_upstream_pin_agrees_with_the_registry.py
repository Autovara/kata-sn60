"""The plugin's default upstream pin must equal the one the deployment registry declares.

Three places named SN60's upstream commit and nothing compared any two of them:

    kata-subnets-deploy registry     upstream_commit      (what every published result claims)
    /srv/kata-bot/.env               KATA_SN60_SANDBOX_COMMIT   (what WINS at runtime)
    kata_sn60.sn60_bitsec            DEFAULT_SANDBOX_COMMIT     (what runs with neither set)

They agreed only by luck. `kata_bot.env_verify` now refuses an environment pin that contradicts the
registry; this closes the third leg, so the fallback cannot quietly become a fourth answer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60.sn60_bitsec import DEFAULT_SANDBOX_COMMIT

REGISTRY = (Path(__file__).resolve().parents[2] / "kata-subnets-deploy" / "registry" / "proposed"
            / "registry.json")


def test_the_plugin_default_is_the_commit_the_registry_declares():
    if not REGISTRY.is_file():
        pytest.skip("kata-subnets-deploy is not checked out beside this repository")

    lanes = json.loads(REGISTRY.read_text(encoding="utf-8"))["lanes"]
    declared = {lane["lane_id"]: lane.get("upstream_commit") for lane in lanes}
    expected = declared.get("sn60__bitsec")
    assert expected, "the registry declares no upstream_commit for sn60__bitsec"
    assert DEFAULT_SANDBOX_COMMIT == expected, (
        f"the plugin defaults to {DEFAULT_SANDBOX_COMMIT}, but the registry declares {expected}. "
        f"A lane running on the default would score a tree every published result names "
        f"differently."
    )
