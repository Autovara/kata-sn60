"""The scoring proxy must be identifiable, pinned, and traceable to the scorer revision.

Upstream runs the judge's proxy under the MUTABLE tag ``bitsec-proxy:latest``, rebuilt from
whatever is on the host and carrying no record of its origin. These pin the three separate claims
that replaces: which image is serving, whether it is the pinned one, and whether it was built from
the tree the lane is scoring against.

Docker is faked here so the rules are testable anywhere; ``test_proxy_image_live.py`` exercises the
same code against a real daemon when one is present.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from kata_sn60.execution.proxy_image import (
    LABEL_SANDBOX_COMMIT,
    LABEL_TREE_SHA256,
    PROXY_IMAGE_DIGEST_ENV,
    ProxyImageError,
    proxy_container,
    verify_proxy_image,
)

COMMIT = "069ae1e2f152370fa97f3397d8a8f8aed5a78539"
TREE = "8fe49c9d820e0ec0cabe7539f9a5b9994a4b9bb52361733562b6b2b36f5dd0bb"
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def _fake_docker(*, image: str = DIGEST, labels: dict | None = None,
                 container_fails: bool = False, image_fails: bool = False):
    """A ``subprocess.run`` stand-in answering the two inspects the module makes."""
    labels = {LABEL_SANDBOX_COMMIT: COMMIT, LABEL_TREE_SHA256: TREE} if labels is None else labels
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        kind = cmd[1]
        if kind == "container":
            if container_fails:
                return subprocess.CompletedProcess(cmd, 1, "", "No such container")
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"Image": image}), "")
        if image_fails:
            return subprocess.CompletedProcess(cmd, 1, "", "No such image")
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"Config": {"Labels": labels}}), "")

    run.calls = calls
    return run


def test_a_matching_pin_and_matching_labels_verify() -> None:
    record = verify_proxy_image(
        expected_sandbox_commit=COMMIT, expected_tree_sha256=TREE,
        env={PROXY_IMAGE_DIGEST_ENV: DIGEST}, runner=_fake_docker(),
    )
    assert record.verified
    assert record.image_digest == DIGEST
    assert record.sandbox_commit == COMMIT
    assert record.as_dict()["verified"] is True


def test_a_different_running_image_fails_closed() -> None:
    """The case a mutable tag makes invisible: the container is serving something else."""
    with pytest.raises(ProxyImageError, match="is running image"):
        verify_proxy_image(
            expected_sandbox_commit=COMMIT, expected_tree_sha256=TREE,
            env={PROXY_IMAGE_DIGEST_ENV: OTHER}, runner=_fake_docker(image=DIGEST),
        )


def test_a_pinned_but_uninspectable_proxy_fails_closed() -> None:
    """"I could not check" must never pass as "it matched" once a pin exists."""
    with pytest.raises(ProxyImageError, match="cannot inspect"):
        verify_proxy_image(
            expected_sandbox_commit=COMMIT,
            env={PROXY_IMAGE_DIGEST_ENV: DIGEST},
            runner=_fake_docker(container_fails=True),
        )


def test_the_pin_is_compared_before_the_image_is_inspected() -> None:
    """A rebuild leaves the old image untagged and often unresolvable, so a stale container's image
    cannot be inspected at all. The mismatch has to be the reported failure, not the inspect."""
    with pytest.raises(ProxyImageError, match="is running image"):
        verify_proxy_image(
            expected_sandbox_commit=COMMIT,
            env={PROXY_IMAGE_DIGEST_ENV: OTHER},
            runner=_fake_docker(image=DIGEST, image_fails=True),
        )


def test_an_image_built_from_a_different_scorer_revision_fails_closed() -> None:
    """The digest proves immutability, never origin. Without the label check, a correctly-pinned
    image built from unrelated sources would sail through."""
    runner = _fake_docker(labels={LABEL_SANDBOX_COMMIT: "0" * 40, LABEL_TREE_SHA256: TREE})
    with pytest.raises(ProxyImageError, match="declares sandbox commit"):
        verify_proxy_image(
            expected_sandbox_commit=COMMIT, expected_tree_sha256=TREE,
            env={PROXY_IMAGE_DIGEST_ENV: DIGEST}, runner=runner,
        )


def test_an_image_built_from_different_bytes_at_the_same_commit_fails_closed() -> None:
    """A commit label alone is the same weak claim a bare `git rev-parse` was."""
    runner = _fake_docker(labels={LABEL_SANDBOX_COMMIT: COMMIT, LABEL_TREE_SHA256: "0" * 64})
    with pytest.raises(ProxyImageError, match="declares sandbox tree"):
        verify_proxy_image(
            expected_sandbox_commit=COMMIT, expected_tree_sha256=TREE,
            env={PROXY_IMAGE_DIGEST_ENV: DIGEST}, runner=runner,
        )


def test_an_unlabelled_image_fails_closed_when_pinned() -> None:
    """Upstream's own build stamps nothing, so the labels being absent is the DEFAULT state of a
    proxy that was not built through tools/build_proxy_image.py."""
    with pytest.raises(ProxyImageError, match="declares sandbox commit"):
        verify_proxy_image(
            expected_sandbox_commit=COMMIT, expected_tree_sha256=TREE,
            env={PROXY_IMAGE_DIGEST_ENV: DIGEST}, runner=_fake_docker(labels={}),
        )


def test_an_unpinned_deployment_is_recorded_rather_than_refused() -> None:
    """Unpinned still scores; it just cannot prove which proxy answered. The record is what makes
    that auditable after the fact instead of only visible in an operator's memory."""
    record = verify_proxy_image(
        expected_sandbox_commit=COMMIT, expected_tree_sha256=TREE,
        env={}, runner=_fake_docker(),
    )
    assert record.verified is False
    assert record.image_digest == DIGEST          # still recorded
    assert PROXY_IMAGE_DIGEST_ENV in record.reason


def test_an_unpinned_deployment_with_no_docker_is_recorded_rather_than_refused() -> None:
    """A host with no proxy yet promised nothing, so it must not be blocked by a check it never
    asked for -- while a PINNED one in the same state still fails closed (above)."""
    record = verify_proxy_image(
        expected_sandbox_commit=COMMIT, env={}, runner=_fake_docker(container_fails=True),
    )
    assert record.verified is False
    assert record.image_digest == ""
    assert "not inspected and not pinned" in record.reason


def test_the_container_name_follows_upstreams_setting() -> None:
    assert proxy_container({}) == "bitsec_proxy"
    assert proxy_container({"KATA_SN60_PROXY_CONTAINER": "other"}) == "other"


def test_the_tree_digest_check_is_skipped_when_there_is_nothing_to_compare() -> None:
    """A clone has no manifest, so there is no tree digest to bind the image to. Empty means
    'cannot check this claim', and must not be treated as a match against an empty label."""
    runner = _fake_docker(labels={LABEL_SANDBOX_COMMIT: COMMIT, LABEL_TREE_SHA256: TREE})
    record = verify_proxy_image(
        expected_sandbox_commit=COMMIT, expected_tree_sha256="",
        env={PROXY_IMAGE_DIGEST_ENV: DIGEST}, runner=runner,
    )
    assert record.verified
