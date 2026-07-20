"""SN60-specific challenge freshness and candidate-only verification.

Kata calls these through plugin verification hooks, leaving shared submission
verification independent from SN60 benchmark details.
"""

from __future__ import annotations

from kata.provenance import short_hash
from kata.state.lanes import benchmark_snapshot_path, load_benchmark_snapshot


def sn60_benchmark_is_current(*, lane_id, summary, public_root=None) -> bool:
    """Freshness against the lane's recorded benchmark snapshot version.

    Gated on the benchmark snapshot version (scorer + sandbox commit) only -- NOT the
    per-run ``freshness_fingerprint`` (which bundles the randomly sampled project keys and
    is never committed, so comparing it would flag every winner as stale). King and
    submission identity are verified separately by the generic verifier.
    """
    if not benchmark_snapshot_path(lane_id, public_root=public_root).exists():
        return False
    snapshot = load_benchmark_snapshot(lane_id, public_root=public_root)
    expected_version = f"{snapshot.scorer_version}@{short_hash(snapshot.sandbox_commit_hash)}"
    return summary.evaluator_version == expected_version


