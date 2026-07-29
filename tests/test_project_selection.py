"""Which projects a SN60 challenge runs.

Merged here from ``kata-bot``, which used to resolve the project set itself and pass it down. Two
resolvers reading the same environment is one resolver too many: the resident's could hand the
plugin a set the plugin's own gates would have refused. The resident now passes nothing.

The stakes are concrete. Select a project the sealed room has no pinned image digest for and the
room returns HTTP 500 mid-round, which closes an innocent candidate as invalid. So the gates here
are fail-closed everywhere: an unusable configuration raises rather than quietly narrowing the set.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata_sn60.validator_system.project_selection import (
    ProjectImageAvailability,
    parse_room_runnable_project_keys_from_env,
    parse_sn60_replicas_per_project_from_env,
    resolve_selectable_project_keys,
    resolve_sn60_project_keys,
    validate_project_images_are_runnable,
)

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_DIGEST_C = "sha256:" + "c" * 64

BENCHMARK_NAME = "curated-highs-only-2025-08-08.json"


def _digests_json(mapping: dict[str, str]) -> str:
    return json.dumps(mapping)


def _sandbox(tmp_path: Path, monkeypatch, project_keys: list[str]) -> Path:
    """A minimal SN60 sandbox mirror: the benchmark snapshot under its required filename."""
    root = tmp_path / "sandbox"
    benchmark = root / "validator" / BENCHMARK_NAME
    benchmark.parent.mkdir(parents=True, exist_ok=True)
    benchmark.write_text(
        json.dumps([{"project_id": key, "vulnerabilities": []} for key in project_keys]) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KATA_SN60_SANDBOX_ROOT", str(root))
    return root


def _pin_nonce(monkeypatch, nonce: str = "nonce-1") -> None:
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.secrets.token_hex",
        lambda _size: nonce,
    )


def _resolve() -> list[str]:
    return resolve_sn60_project_keys(
        configured_keys=None, sandbox_root=None, benchmark_file=None, sandbox_commit=None
    )


@pytest.fixture
def sampling(monkeypatch):
    monkeypatch.delenv("KATA_SN60_PROJECT_KEYS", raising=False)
    monkeypatch.delenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", raising=False)
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "challenge-secret")
    _pin_nonce(monkeypatch)


# ---- sampled mode --------------------------------------------------------------------------

def test_it_samples_the_configured_number_of_projects(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5", "p6"])
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")

    selected = _resolve()

    assert len(selected) == 3
    assert len(set(selected)) == 3
    assert set(selected) <= {"p1", "p2", "p3", "p4", "p5", "p6"}


def test_the_same_seed_selects_the_same_projects(tmp_path, monkeypatch, sampling) -> None:
    """The draw must be a function of the secret and nonce alone, so a challenge can be explained
    after the fact rather than being unreproducible noise."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5", "p6"])
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")

    assert _resolve() == _resolve()


def test_a_different_nonce_can_select_different_projects(tmp_path, monkeypatch, sampling) -> None:
    """A fresh nonce per round is what stops a miner pre-computing the project set and overfitting
    to it. If the nonce did not move the draw, that defence would be inert."""
    _sandbox(tmp_path, monkeypatch, [f"p{i}" for i in range(1, 21)])
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "4")

    draws = set()
    for nonce in range(12):
        _pin_nonce(monkeypatch, f"nonce-{nonce}")
        draws.add(tuple(_resolve()))
    assert len(draws) > 1


def test_sampling_without_a_secret_is_refused(tmp_path, monkeypatch, sampling) -> None:
    """Without a secret the draw is predictable from the key names alone, so every miner could
    pre-compute the project set. Refuse rather than run a guessable challenge."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "   ")

    with pytest.raises(ValueError, match="SAMPLE_SECRET"):
        _resolve()


def test_asking_for_the_whole_benchmark_needs_no_secret(tmp_path, monkeypatch, sampling) -> None:
    """Nothing is narrowed, so there is no draw to keep secret."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3"])
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")
    monkeypatch.delenv("KATA_SN60_PROJECT_SAMPLE_SECRET", raising=False)

    assert _resolve() == ["p1", "p2", "p3"]


def test_no_sample_size_runs_the_whole_benchmark(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3"])
    monkeypatch.delenv("KATA_SN60_PROJECT_SAMPLE_SIZE", raising=False)

    assert _resolve() == ["p1", "p2", "p3"]


# ---- mixed mode: fixed keys plus a sampled remainder -----------------------------------------

def test_fixed_projects_always_run_and_come_first(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5", "p6"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p2, p5")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "4")

    selected = _resolve()

    assert selected[:2] == ["p2", "p5"]
    assert len(selected) == 4
    assert len(set(selected)) == 4, "a fixed key must never be drawn again as part of the sample"
    assert set(selected[2:]) <= {"p1", "p3", "p4", "p6"}


def test_fixed_keys_filling_the_sample_leave_nothing_to_draw(
    tmp_path, monkeypatch, sampling
) -> None:
    """The boundary case: sample_size == len(fixed). There is no remainder, and asking the sampler
    for zero more projects must not be treated as an invalid sample size."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1,p3")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    assert _resolve() == ["p1", "p3"]


def test_more_fixed_keys_than_the_sample_holds_is_refused(
    tmp_path, monkeypatch, sampling
) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1,p2,p3")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    with pytest.raises(ValueError, match="must not contain more keys"):
        _resolve()


def test_fixed_keys_need_a_sample_size(tmp_path, monkeypatch, sampling) -> None:
    """Without one, "fixed" would silently mean "the whole benchmark, in a particular order"."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1")
    monkeypatch.delenv("KATA_SN60_PROJECT_SAMPLE_SIZE", raising=False)

    with pytest.raises(ValueError, match="SAMPLE_SIZE"):
        _resolve()


def test_a_sample_as_large_as_the_benchmark_defeats_fixing(
    tmp_path, monkeypatch, sampling
) -> None:
    """If the sample is the whole benchmark, pinning a project inside it means nothing."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")

    with pytest.raises(ValueError, match="smaller than the benchmark"):
        _resolve()


def test_duplicate_fixed_keys_are_refused(tmp_path, monkeypatch, sampling) -> None:
    """A duplicate would consume two of the sample's slots for one project."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1,p1")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")

    with pytest.raises(ValueError, match="duplicate"):
        _resolve()


def test_a_fixed_key_outside_the_benchmark_is_refused(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p9")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    with pytest.raises(ValueError, match="not present in the benchmark"):
        _resolve()


def test_fixed_keys_and_explicit_keys_cannot_be_combined(tmp_path, monkeypatch, sampling) -> None:
    """Two selection modes at once has no defined answer; say so rather than pick one."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1")
    monkeypatch.setenv("KATA_SN60_PROJECT_KEYS", "p2")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    with pytest.raises(ValueError, match="cannot be combined"):
        _resolve()


def test_keys_passed_on_the_command_win_over_a_fixed_set(tmp_path, monkeypatch, sampling) -> None:
    """An operator naming projects explicitly on the challenge command is a deliberate one-off
    override, not the env-var collision above."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    assert resolve_sn60_project_keys(
        configured_keys=["p3"], sandbox_root=None, benchmark_file=None, sandbox_commit=None
    ) == ["p3"]


# ---- the room's digest map is the authoritative runnable set ---------------------------------

def test_an_unset_digest_map_leaves_the_gate_open(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    assert parse_room_runnable_project_keys_from_env() is None


def test_only_well_formed_digests_count(monkeypatch) -> None:
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        _digests_json({"a": _DIGEST_A, "b": "not-a-digest", "c": "", "d": _DIGEST_C}),
    )
    assert parse_room_runnable_project_keys_from_env() == {"a", "d"}


def test_a_padded_digest_is_rejected_because_the_room_rejects_it(monkeypatch) -> None:
    """The room does not trim, so neither may this. A value the selector trimmed and accepted but
    the room rejected would let an unrunnable project through -- the divergence being closed."""
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        _digests_json({"a": _DIGEST_A, "b": f"  {_DIGEST_B}  "}),
    )
    assert parse_room_runnable_project_keys_from_env() == {"a"}


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("{}", "no well-formed"),
        (json.dumps({"a": "not-a-digest"}), "no well-formed"),
        (json.dumps({"a": f" {_DIGEST_A} "}), "no well-formed"),
        ("{not json", "JSON object"),
        (json.dumps(["a", "b"]), "JSON object"),
    ],
)
def test_an_unusable_digest_map_fails_closed(monkeypatch, value, match) -> None:
    """Only a TRULY UNSET variable may skip the gate. Present-but-unusable means the room can run
    nothing, so falling back to the docker probe would reopen the divergence it exists to close."""
    monkeypatch.setenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", value)
    with pytest.raises(ValueError, match=match):
        parse_room_runnable_project_keys_from_env()


def test_selectable_is_the_benchmark_intersected_with_the_map(monkeypatch) -> None:
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        _digests_json({"proj-a": _DIGEST_A, "proj-c": _DIGEST_C}),
    )
    assert resolve_selectable_project_keys(["proj-a", "proj-b", "proj-c", "proj-d"]) == [
        "proj-a",
        "proj-c",
    ]


def test_the_map_supersedes_the_docker_probe(monkeypatch) -> None:
    """The map is authoritative and needs no docker access; probing anyway would make selection
    depend on whatever the local daemon happens to have cached."""
    monkeypatch.setenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", _digests_json({"proj-a": _DIGEST_A}))
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "true")

    def _boom(_keys, **_kwargs):
        raise AssertionError("docker probe must not run when the digest map is authoritative")

    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.check_project_image_availability", _boom
    )
    assert resolve_selectable_project_keys(["proj-a", "proj-b"]) == ["proj-a"]


def test_a_benchmark_with_nothing_pinned_is_refused(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", _digests_json({"other": _DIGEST_A}))
    with pytest.raises(ValueError, match="pinned"):
        resolve_selectable_project_keys(["proj-a", "proj-b"])


def test_sampling_never_selects_an_unpinned_project(tmp_path, monkeypatch, sampling) -> None:
    """The regression this gate exists for: the draw used to be taken from the whole benchmark and
    could land on a project the room had no digest for, which 500'd mid-round."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5"])
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        _digests_json({"p2": _DIGEST_A, "p4": _DIGEST_B, "p5": _DIGEST_C}),
    )
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    for nonce in range(40):
        _pin_nonce(monkeypatch, f"nonce-{nonce}")
        selected = _resolve()
        assert len(selected) == 2
        assert set(selected) <= {"p2", "p4", "p5"}


def test_a_sample_larger_than_the_pinned_set_is_refused(tmp_path, monkeypatch, sampling) -> None:
    """Better to refuse than to quietly run a smaller challenge than the operator configured."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5"])
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON", _digests_json({"p2": _DIGEST_A, "p4": _DIGEST_B})
    )
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")

    with pytest.raises(ValueError, match="only 2"):
        _resolve()


def test_a_fixed_key_the_room_cannot_run_is_refused(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        _digests_json({"p2": _DIGEST_A, "p3": _DIGEST_B, "p4": _DIGEST_C}),
    )
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p1")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    with pytest.raises(ValueError, match="cannot run"):
        _resolve()


def test_explicit_keys_must_all_be_pinned(monkeypatch) -> None:
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON", _digests_json({"p1": _DIGEST_A, "p2": _DIGEST_B})
    )
    validate_project_images_are_runnable(["p1", "p2"])
    with pytest.raises(ValueError, match="pinned room image digest"):
        validate_project_images_are_runnable(["p1", "p3"])


def test_explicit_keys_are_gated_by_the_map_even_with_the_probe_flag_off(
    tmp_path, monkeypatch
) -> None:
    """The flag governs the docker probe only. The map is not optional."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2"])
    monkeypatch.delenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", raising=False)
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "false")
    monkeypatch.setenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", _digests_json({"p1": _DIGEST_A}))

    monkeypatch.setenv("KATA_SN60_PROJECT_KEYS", "p1, p3")
    with pytest.raises(ValueError, match="pinned room image digest"):
        _resolve()

    monkeypatch.setenv("KATA_SN60_PROJECT_KEYS", "p1")
    assert _resolve() == ["p1"]


# ---- the docker probe, for deployments with no pinned map ------------------------------------

def _availability(unavailable: set[str]):
    def _probe(project_keys, **_kwargs):
        return {
            key: ProjectImageAvailability(
                project_key=key,
                image=f"ghcr.io/bitsec-ai/{key}:latest",
                runnable=key not in unavailable,
                source="test",
                detail="denied" if key in unavailable else "",
            )
            for key in project_keys
        }

    return _probe


def test_the_probe_narrows_the_draw_to_runnable_images(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5", "p6"])
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "true")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.check_project_image_availability",
        _availability({"p2", "p4"}),
    )

    selected = _resolve()

    assert len(selected) == 3
    assert set(selected) <= {"p1", "p3", "p5", "p6"}


def test_the_probe_is_skipped_when_the_flag_is_off(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3"])
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "false")
    monkeypatch.delenv("KATA_SN60_PROJECT_SAMPLE_SIZE", raising=False)

    def _boom(_keys, **_kwargs):
        raise AssertionError("the probe must not run when it is switched off")

    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.check_project_image_availability", _boom
    )
    assert _resolve() == ["p1", "p2", "p3"]


def test_no_runnable_image_at_all_is_refused(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2"])
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "true")
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.check_project_image_availability",
        _availability({"p1", "p2"}),
    )

    with pytest.raises(ValueError, match="runnable Docker images"):
        _resolve()


def test_an_unrunnable_fixed_project_is_refused(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "true")
    monkeypatch.setenv("KATA_SN60_CHALLENGE_FIXED_PROJECT_KEYS", "p2")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.check_project_image_availability",
        _availability({"p2"}),
    )

    with pytest.raises(ValueError, match="cannot run"):
        _resolve()


def test_unrunnable_explicit_keys_are_refused(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    monkeypatch.setenv("KATA_SN60_REQUIRE_RUNNABLE_PROJECT_IMAGES", "true")
    monkeypatch.setattr(
        "kata_sn60.validator_system.project_selection.check_project_image_availability",
        _availability({"p2"}),
    )

    with pytest.raises(ValueError, match="not runnable: p2"):
        validate_project_images_are_runnable(["p1", "p2"])


# ---- replicas per project --------------------------------------------------------------------

def test_replicas_default_to_unset(monkeypatch) -> None:
    """``None`` means "caller decides", which is what lets the plugin apply its own default rather
    than this module inventing one."""
    monkeypatch.delenv("KATA_SN60_REPLICAS_PER_PROJECT", raising=False)
    assert parse_sn60_replicas_per_project_from_env() is None
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "   ")
    assert parse_sn60_replicas_per_project_from_env() is None


def test_replicas_are_read_from_the_env(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "3")
    assert parse_sn60_replicas_per_project_from_env() == 3


@pytest.mark.parametrize("value", ["0", "-1", "three", "3.5"])
def test_an_unusable_replica_count_is_refused(monkeypatch, value) -> None:
    """Silently falling back to 1 would score a third of the configured work and look successful."""
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", value)
    with pytest.raises(ValueError):
        parse_sn60_replicas_per_project_from_env()


# ---- the plugin applies the env replica count ------------------------------------------------

def _plugin():
    from kata_sn60.plugin import Sn60BitsecPlugin

    return Sn60BitsecPlugin()


def test_the_plugin_takes_replicas_from_the_env_when_the_lane_is_silent(monkeypatch) -> None:
    """The regression that motivated the move: with no ``replicas_per_project`` in the challenge
    config the count used to fall back to 1, so a deployment configured for 3 scored a third of its
    work and reported success."""
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "3")
    assert _plugin()._replicas_per_project({}) == 3


def test_the_lane_config_still_wins_over_the_env(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "3")
    assert _plugin()._replicas_per_project({"replicas_per_project": 5}) == 5


def test_replicas_fall_back_to_one_only_when_nothing_says_otherwise(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_REPLICAS_PER_PROJECT", raising=False)
    assert _plugin()._replicas_per_project({}) == 1


def test_the_budget_bound_uses_the_same_replica_count(tmp_path, monkeypatch) -> None:
    """The bound is reserved BEFORE the paid phase. Resolving replicas differently here would
    reserve for fewer runs than the challenge executes, and the cap would be blown mid-round."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2"])
    monkeypatch.delenv("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", raising=False)
    monkeypatch.setenv("KATA_SN60_PROJECT_KEYS", "p1, p2")
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "3")

    with_env = _plugin().capacity_estimate(config={})["tee_runs"]
    with_lane = _plugin().capacity_estimate(config={"replicas_per_project": 3})["tee_runs"]

    assert with_env == with_lane
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "1")
    assert _plugin().capacity_estimate(config={})["tee_runs"] < with_env


# ---- preflight runs the real selection -------------------------------------------------------

def test_preflight_is_silent_on_a_workable_deployment(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")

    # Errors only: preflight also reports proxy-image pinning, which has its own tests and is
    # a warning about the deployment rather than a problem with project selection.
    assert [i for i in _plugin().preflight() if i["level"] == "error"] == []


def test_preflight_reports_what_the_round_would_have_raised(
    tmp_path, monkeypatch, sampling
) -> None:
    """Preflight and selection are the SAME code, so they cannot drift apart and let a round start
    that the round itself then refuses."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5"])
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON", _digests_json({"p2": _DIGEST_A, "p4": _DIGEST_B})
    )
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")  # only 2 are pinned

    issues = _plugin().preflight()

    errors = [issue for issue in issues if issue["level"] == "error"]
    assert [issue["level"] for issue in errors] == ["error"]
    assert "only 2" in errors[0]["message"]


def test_preflight_reports_an_unusable_replica_count(tmp_path, monkeypatch, sampling) -> None:
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4"])
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "0")

    issues = _plugin().preflight()

    assert any("REPLICAS_PER_PROJECT" in issue["message"] for issue in issues)


def test_preflight_reports_every_problem_not_just_the_first(
    tmp_path, monkeypatch, sampling
) -> None:
    """An operator fixing one variable per restart is an operator restarting all evening."""
    _sandbox(tmp_path, monkeypatch, ["p1", "p2", "p3", "p4", "p5"])
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON", _digests_json({"p2": _DIGEST_A, "p4": _DIGEST_B})
    )
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")
    monkeypatch.setenv("KATA_SN60_REPLICAS_PER_PROJECT", "nope")

    assert len([i for i in _plugin().preflight() if i["level"] == "error"]) == 2


def test_a_missing_benchmark_is_reported_not_raised(tmp_path, monkeypatch, sampling) -> None:
    """Preflight exists to turn a crash into a message. A raise here would take the whole
    ``check-validator-env`` command down instead of reporting the one broken lane."""
    monkeypatch.setenv("KATA_SN60_SANDBOX_ROOT", str(tmp_path / "nothing-here"))
    monkeypatch.delenv("KATA_SN60_BENCHMARK_FILE", raising=False)

    issues = _plugin().preflight()

    assert any(issue["level"] == "error" for issue in issues)
