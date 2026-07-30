"""Persistent per-project cache of the SN60 king's benchmark scores.

The king's score on a given project is stable for a fixed king artifact and a
fixed benchmark, so re-running the king every duel/challenge is wasted inference.
This module caches the king's per-project execution + evaluation payloads keyed
by ``(king_hash, benchmark_version)``.

Correctness comes from the key: a cached entry is only ever reused when both the
king hash and the benchmark version match the current king and benchmark, which
means the king code and the answer key are byte-identical and the score is
therefore unchanged. A new king (different hash) or an edited benchmark
(different version) can never serve a stale score -- the cache invalidates
itself implicitly, with nothing to clear by hand.

Storage is deliberately free of any ``sn60_bitsec`` import so the evaluator can
depend on this module without a cycle.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


def benchmark_version_key(scorer_version: str, benchmark_sha256: str) -> str:
    """Identity of the scorer + answer key that produced a king score.

    Includes the benchmark content hash (not just a commit) so an edited
    benchmark file forces a recompute even without a sandbox commit change.
    """
    return f"{scorer_version}@{benchmark_sha256}"



def _is_recorded_run(entry: object) -> bool:
    """Whether a scoreboard slot holds a real recorded run rather than a gap.

    ``None`` is the marker this code writes for a gap. The empty-dict form is recognised too,
    because scoreboards written before that fix are still on disk and resuming one must not replay
    its placeholders as results.
    """
    if not isinstance(entry, dict):
        return False
    return bool(entry.get("report")) or bool(entry.get("evaluation"))

@dataclass
class KingScoreboard:
    """Cached king runs for one ``(king_hash, benchmark_version)``.

    ``scores`` maps a project key to the list of per-replica runs recorded so
    far; each run holds the raw execution ``report`` and ``evaluation`` payloads
    so a cache hit can materialize identical artifacts without re-running.
    """

    king_hash: str
    benchmark_version: str
    scores: dict[str, list[dict[str, object]]] = field(default_factory=dict)

    def cached_run(self, project_key: str, replica_index: int) -> dict[str, object] | None:
        """Return the cached run for a 1-based replica index, or ``None``.

        A GAP is a miss, not a hit. ``record_run`` has to lengthen the list when replicas finish
        out of order -- which they routinely do, since ``KATA_SN60_PROJECT_CONCURRENCY`` runs three
        at once -- and the slots it skips over are placeholders standing in for work that has not
        happened yet. Returning one as though it were a cached result told the caller "this replica
        is already done" and handed it an empty payload.

        The cost was silent and paid: the replica had already made its sealed-room call, so the
        report existed and the money was spent, but its evaluation was replaced with ``{}`` and the
        run was counted invalid. Which replicas lost depended purely on completion order.
        """
        runs = self.scores.get(project_key)
        if runs is None or replica_index < 1 or replica_index > len(runs):
            return None
        entry = runs[replica_index - 1]
        if not _is_recorded_run(entry):
            return None
        return entry

    def record_run(
        self,
        project_key: str,
        replica_index: int,
        report_payload: dict[str, object],
        evaluation_payload: dict[str, object],
    ) -> None:
        """Store a freshly-computed king run at its 1-based replica index."""
        runs = self.scores.setdefault(project_key, [])
        entry: dict[str, object] = {
            "report": report_payload,
            "evaluation": evaluation_payload,
        }
        if replica_index - 1 < len(runs):
            runs[replica_index - 1] = entry
        else:
            # Replicas finish OUT OF ORDER under concurrency, so a later index can be recorded
            # first and the list has to be lengthened past the ones still running. ``None`` marks
            # those as "not yet recorded" -- an empty dict looked like a real cached run and was
            # served as one, discarding the still-running replica's result. See ``cached_run``.
            while len(runs) < replica_index - 1:
                runs.append(None)
            runs.append(entry)


def load_king_scoreboard(
    path: str | Path,
    *,
    king_hash: str,
    benchmark_version: str,
) -> KingScoreboard:
    """Load the scoreboard for the current king+benchmark, or a fresh empty one.

    A file whose stored key does not match the current ``(king_hash,
    benchmark_version)`` is stale and ignored: the returned board starts empty
    and overwrites the stale file on the next save.
    """
    board_path = Path(path)
    if board_path.exists():
        try:
            data = json.loads(board_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None
        if (
            isinstance(data, dict)
            and data.get("king_hash") == king_hash
            and data.get("benchmark_version") == benchmark_version
            and isinstance(data.get("scores"), dict)
        ):
            return KingScoreboard(
                king_hash=king_hash,
                benchmark_version=benchmark_version,
                scores=data["scores"],
            )
    return KingScoreboard(king_hash=king_hash, benchmark_version=benchmark_version)


def save_king_scoreboard(path: str | Path, board: KingScoreboard) -> None:
    """Atomically persist the scoreboard."""
    board_path = Path(path)
    board_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "king_hash": board.king_hash,
        "benchmark_version": board.benchmark_version,
        "scores": board.scores,
    }
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{board_path.name}.",
        suffix=".tmp",
        dir=board_path.parent,
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        tmp_path.replace(board_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
