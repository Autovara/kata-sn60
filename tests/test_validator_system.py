from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60.sn60_bitsec import Sn60SandboxSource
from kata_sn60.validator_system.project_selection import (
    parse_room_runnable_project_keys_from_env,
    parse_sn60_project_keys_from_env,
    resolve_sn60_project_keys,
    sample_sn60_project_keys,
)

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_C = "sha256:" + "c" * 64


def _mock_benchmark_source(monkeypatch, tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark = write_benchmark(sandbox_root)
    source = Sn60SandboxSource(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark),
        benchmark_sha256="benchmark",
        sandbox_commit="sandbox",
        scorer_version="ScaBenchScorerV2",
    )
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.resolve_sn60_sandbox_source",
        lambda **_kwargs: source,
    )


def write_benchmark(root: Path) -> Path:
    benchmark = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark.parent.mkdir(parents=True, exist_ok=True)
    benchmark.write_text(
        json.dumps(
            [
                {"project_id": "proj-a"},
                {"project_id": "proj-b"},
                {"project_id": "proj-c"},
                {"project_id": "proj-d"},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark


def test_parse_sn60_project_keys_from_env(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_PROJECT_KEYS", " proj-a,proj-b ,, proj-c ")

    assert parse_sn60_project_keys_from_env() == ["proj-a", "proj-b", "proj-c"]


def test_sample_sn60_project_keys_is_stable_and_dedupes() -> None:
    sample = sample_sn60_project_keys(
        ["proj-c", "proj-a", "proj-c", "proj-b"],
        sample_size=2,
        sample_secret="secret",
        sample_nonce="nonce",
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )

    assert sample == sample_sn60_project_keys(
        ["proj-c", "proj-a", "proj-c", "proj-b"],
        sample_size=2,
        sample_secret="secret",
        sample_nonce="nonce",
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )
    assert len(sample) == 2
    assert len(set(sample)) == 2


def test_resolve_sn60_project_keys_samples_benchmark(tmp_path: Path, monkeypatch) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark = write_benchmark(sandbox_root)
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "secret")
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.secrets.token_hex",
        lambda _size: "nonce",
    )

    source = Sn60SandboxSource(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark),
        benchmark_sha256="benchmark",
        sandbox_commit="sandbox",
        scorer_version="ScaBenchScorerV2",
    )
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.resolve_sn60_sandbox_source",
        lambda **_kwargs: source,
    )
    selected = resolve_sn60_project_keys(
        configured_keys=None,
        sandbox_root=None,
        benchmark_file=None,
        sandbox_commit=None,
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )

    assert selected == sample_sn60_project_keys(
        ["proj-a", "proj-b", "proj-c", "proj-d"],
        sample_size=2,
        sample_secret="secret",
        sample_nonce="nonce",
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )


# --- room digest map gates engine-side selection (S1e-followup) --------------------------------

def test_digest_map_constrains_selection_to_pinned(tmp_path: Path, monkeypatch) -> None:
    _mock_benchmark_source(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        json.dumps({"proj-a": _DIGEST_A, "proj-c": _DIGEST_C}),
    )
    # benchmark is proj-a..d; only a,c are pinned; no sample size -> all pinned, order preserved.
    selected = resolve_sn60_project_keys(
        configured_keys=None, sandbox_root=None, benchmark_file=None, sandbox_commit=None
    )
    assert selected == ["proj-a", "proj-c"]


def test_digest_map_sampling_never_picks_unpinned(tmp_path: Path, monkeypatch) -> None:
    _mock_benchmark_source(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        json.dumps({"proj-a": _DIGEST_A, "proj-c": _DIGEST_C}),
    )
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "1")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "secret")
    pinned = {"proj-a", "proj-c"}
    for n in range(40):
        monkeypatch.setattr(
            "kata_sn60.validator_system.project_selection.secrets.token_hex",
            lambda _size, _n=n: f"nonce-{_n}",
        )
        sel = resolve_sn60_project_keys(
            configured_keys=None, sandbox_root=None, benchmark_file=None, sandbox_commit=None
        )
        assert len(sel) == 1 and set(sel) <= pinned


def test_digest_map_with_no_pinned_benchmark_project_raises(tmp_path: Path, monkeypatch) -> None:
    _mock_benchmark_source(monkeypatch, tmp_path)
    monkeypatch.setenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", json.dumps({"other": _DIGEST_A}))
    with pytest.raises(ValueError, match="pinned"):
        resolve_sn60_project_keys(
            configured_keys=None, sandbox_root=None, benchmark_file=None, sandbox_commit=None
        )


def test_explicit_keys_must_be_pinned(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", json.dumps({"proj-a": _DIGEST_A}))
    assert resolve_sn60_project_keys(
        configured_keys=["proj-a"], sandbox_root=None, benchmark_file=None, sandbox_commit=None
    ) == ["proj-a"]
    with pytest.raises(ValueError, match="no pinned room image digest|pinned"):
        resolve_sn60_project_keys(
            configured_keys=["proj-a", "proj-x"],
            sandbox_root=None,
            benchmark_file=None,
            sandbox_commit=None,
        )


def test_present_but_empty_digest_map_fails_closed(monkeypatch) -> None:
    for value in ("", "   ", "{}"):
        monkeypatch.setenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", value)
        with pytest.raises(ValueError):
            parse_room_runnable_project_keys_from_env()


def test_unset_digest_map_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    assert parse_room_runnable_project_keys_from_env() is None


def test_padded_digest_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        json.dumps({"proj-a": _DIGEST_A, "proj-b": f"  {_DIGEST_C}  "}),
    )
    assert parse_room_runnable_project_keys_from_env() == {"proj-a"}
