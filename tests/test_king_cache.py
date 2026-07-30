from __future__ import annotations

import json
from pathlib import Path

from kata_sn60.king_cache import (
    KingScoreboard,
    benchmark_version_key,
    load_king_scoreboard,
    save_king_scoreboard,
)


def test_benchmark_version_key_combines_scorer_and_benchmark_hash() -> None:
    assert benchmark_version_key("ScaBenchScorerV2", "abc123") == "ScaBenchScorerV2@abc123"


def test_record_and_read_runs_by_replica_index() -> None:
    board = KingScoreboard(king_hash="k1", benchmark_version="v1")
    assert board.cached_run("proj", 1) is None

    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    board.record_run("proj", 2, {"success": False}, {"status": "error"})

    assert board.cached_run("proj", 1) == {
        "report": {"success": True},
        "evaluation": {"status": "success"},
    }
    assert board.cached_run("proj", 2)["evaluation"] == {"status": "error"}
    assert board.cached_run("proj", 3) is None
    assert board.cached_run("other", 1) is None


def test_scoreboard_roundtrips_through_disk(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="k1", benchmark_version="v1")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)

    loaded = load_king_scoreboard(path, king_hash="k1", benchmark_version="v1")
    assert loaded.cached_run("proj", 1) == {
        "report": {"success": True},
        "evaluation": {"status": "success"},
    }


def test_stale_king_hash_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="old-king", benchmark_version="v1")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)

    fresh = load_king_scoreboard(path, king_hash="new-king", benchmark_version="v1")
    assert fresh.king_hash == "new-king"
    assert fresh.scores == {}


def test_stale_benchmark_version_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="k1", benchmark_version="old-benchmark")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)

    fresh = load_king_scoreboard(path, king_hash="k1", benchmark_version="new-benchmark")
    assert fresh.scores == {}


def test_corrupt_scoreboard_file_falls_back_to_empty(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    path.write_text("{ not json", encoding="utf-8")
    board = load_king_scoreboard(path, king_hash="k1", benchmark_version="v1")
    assert board.scores == {}


def test_save_is_atomic_and_leaves_no_temp_file(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="k1", benchmark_version="v1")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)
    assert path.exists()
    assert not path.with_name(path.name + ".tmp").exists()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["king_hash"] == "k1"
    assert on_disk["benchmark_version"] == "v1"


# --- a gap in the scoreboard is a MISS, not a hit ------------------------------------------------


def test_an_out_of_order_record_does_not_fabricate_hits_for_the_replicas_still_running() -> None:
    """The live bug. Replicas run three at a time and finish out of order, so a later index gets
    recorded first and the list is lengthened past the ones still going. Those skipped slots used
    to be empty dicts, and ``cached_run`` served them as real results -- telling a replica that had
    ALREADY made its paid sealed-room call that it was done, and replacing its evaluation with
    ``{}``. It was then counted invalid. Which replicas lost depended purely on completion order,
    which is why the count moved between rounds (5, then 3 of 21)."""
    board = KingScoreboard(king_hash="k", benchmark_version="v")

    # Replica 3 wins the race and records first.
    board.record_run("p", 3, {"success": True}, {"status": "success"})

    # Replicas 1 and 2 are still running: their slots must read as MISSES.
    assert board.cached_run("p", 1) is None
    assert board.cached_run("p", 2) is None
    assert board.cached_run("p", 3) == {
        "report": {"success": True},
        "evaluation": {"status": "success"},
    }

    # ...and when they finish, they record normally.
    board.record_run("p", 1, {"success": False}, {"status": "success", "result": {"r": 1}})
    assert board.cached_run("p", 1)["evaluation"]["result"] == {"r": 1}
    assert board.cached_run("p", 2) is None


def test_a_scoreboard_written_before_the_fix_does_not_replay_its_placeholders() -> None:
    """Existing checkpoints on disk still carry the empty-dict form. Resuming one must treat those
    as gaps too, or the very first resumed round reproduces the bug from persisted state."""
    board = KingScoreboard(
        king_hash="k", benchmark_version="v",
        scores={"p": [{"report": {}, "evaluation": {}}, {"report": {}, "evaluation": {}},
                      {"report": {"success": True}, "evaluation": {"status": "success"}}]},
    )
    assert board.cached_run("p", 1) is None
    assert board.cached_run("p", 2) is None
    assert board.cached_run("p", 3) is not None


def test_gaps_survive_a_save_and_load_round_trip(tmp_path) -> None:
    """The gap marker has to persist: a round interrupted mid-project writes the scoreboard with
    holes in it, and the resume must still see them as work to do."""
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="k", benchmark_version="v")
    board.record_run("p", 3, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)

    reloaded = load_king_scoreboard(path, king_hash="k", benchmark_version="v")
    assert reloaded.cached_run("p", 1) is None
    assert reloaded.cached_run("p", 2) is None
    assert reloaded.cached_run("p", 3) is not None


def test_a_recorded_run_is_still_a_hit_even_when_the_agent_produced_nothing() -> None:
    """A legitimately empty REPORT (agent found nothing) is a real result and must stay cached --
    the miss test is 'was anything recorded', not 'is the payload interesting'."""
    board = KingScoreboard(king_hash="k", benchmark_version="v")
    board.record_run("p", 1, {}, {"status": "success", "result": {"detection_rate": 0.0}})
    hit = board.cached_run("p", 1)
    assert hit is not None and hit["evaluation"]["result"]["detection_rate"] == 0.0
