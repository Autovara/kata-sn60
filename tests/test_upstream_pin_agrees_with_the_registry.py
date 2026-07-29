"""SN60's upstream pin must have exactly ONE source of truth.

Three places once named SN60's upstream commit and nothing compared any two of them:

    kata-subnets-deploy registry     upstream_commit            (what every published result claims)
    /srv/kata-bot/.env               KATA_SN60_SANDBOX_COMMIT   (what WINS at runtime)
    kata_sn60.sn60_bitsec            DEFAULT_SANDBOX_COMMIT     (what runs with neither set)

They agreed only by luck. That is now settled by REMOVING two of them rather than by comparing all
three: the lane is a ``vendor`` integration, so the registry declares no upstream pin at all, and
the plugin's own ``SANDBOX_MANIFEST.json`` is the single authority -- a manifest that binds the
commit to the digest of every file in the tree, which a bare commit id never did.

``kata_bot.env_verify`` still refuses an environment pin that contradicts a registry that declares
one; with none declared there is nothing left to contradict.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60 import sandbox_snapshot
from kata_sn60.sn60_bitsec import DEFAULT_SANDBOX_COMMIT

REGISTRY = (Path(__file__).resolve().parents[2] / "kata-subnets-deploy" / "registry" / "proposed"
            / "registry.json")


def _sn60_lane() -> dict:
    if not REGISTRY.is_file():
        pytest.skip("kata-subnets-deploy is not checked out beside this repository")
    lanes = json.loads(REGISTRY.read_text(encoding="utf-8"))["lanes"]
    lane = next((entry for entry in lanes if entry.get("lane_id") == "sn60__bitsec"), None)
    assert lane is not None, "the registry has no sn60__bitsec lane"
    return lane


def test_the_lane_vendors_its_upstream_rather_than_cloning_it():
    """``clone`` meant a checkout at ``/srv/sandbox`` whose provenance was a commit id and nothing
    more -- a dirty worktree, a modified scorer or an extra file all passed."""
    assert _sn60_lane()["integration_mode"] == "vendor"


def test_the_registry_declares_no_second_pin():
    """A vendor lane that also named a commit would be a second answer that can drift from the
    manifest, which is the exact failure this consolidation removes."""
    lane = _sn60_lane()
    assert "upstream_commit" not in lane
    assert "upstream_repo" not in lane


def test_the_manifest_is_the_single_source_of_truth_for_the_pin():
    """What replaced the registry field: the commit is bound to the bytes it names."""
    document = sandbox_snapshot.manifest(sandbox_snapshot.vendored_root())
    assert document["upstream_commit"] == DEFAULT_SANDBOX_COMMIT
    assert document["upstream_repo"] == sandbox_snapshot.UPSTREAM_REPO
    assert sandbox_snapshot.verify(sandbox_snapshot.vendored_root()).ok


def test_the_lane_is_granted_no_write_access_to_a_sandbox_checkout():
    """The grant existed only because the scorer ran with ``cwd`` inside the verified tree. It runs
    on a scratch workspace now, so the retirement has to reach the unit params too -- otherwise the
    privilege outlives the reason for it."""
    readwrite = _sn60_lane()["unit_params"]["readwrite_paths"]
    assert "/srv/sandbox" not in readwrite
    assert readwrite == ["/srv/kata", "/srv/kata-bot"]
