"""Identity of the scoring proxy the judge's inference actually goes through.

Every judge call is answered by a container, so "which code answered" belongs in the provenance of
every score exactly as much as which scorer revision ran. Upstream names that container by the
MUTABLE tag ``bitsec-proxy:latest`` (``validator/manager.py``), rebuilt from whatever is on the
host and carrying no record of its origin. Two hosts can serve different code under that one name
and nothing notices.

Three separate claims are checked here, because a digest alone answers only the first:

1. **Which image is running.** Read from the live container, not from a tag: a tag is a movable
   label, and the question is what is serving right now, not what the label points at today.
2. **Is it the pinned one.** Compared against ``KATA_SN60_PROXY_IMAGE_DIGEST``. A mismatch fails
   closed -- an unexpected proxy is exactly the case where continuing would spend validator money
   on an answer nobody can attribute.
3. **Was it built from the scorer revision being scored.** The digest proves immutability, never
   origin. ``tools/build_proxy_image.py`` stamps the sandbox commit and tree digest into image
   labels at build time, and they are re-checked here against the tree the lane resolved, so
   "built from the verified source" is a checkable property rather than a runbook promise.

Unpinned is allowed and REPORTED, never silently accepted: the lane's ``preflight`` surfaces it, so
an operator sees "this deployment is not pinned" instead of discovering it after a bad round.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any

#: Build-time labels ``tools/build_proxy_image.py`` stamps and this module verifies.
LABEL_SANDBOX_COMMIT = "ai.kata.sn60.sandbox_commit"
LABEL_TREE_SHA256 = "ai.kata.sn60.sandbox_tree_sha256"

#: The tag upstream's manager builds and runs the proxy under.
DEFAULT_PROXY_IMAGE_TAG = "bitsec-proxy:latest"
#: The container name upstream's ``settings.proxy_container`` uses.
DEFAULT_PROXY_CONTAINER = "bitsec_proxy"

PROXY_IMAGE_DIGEST_ENV = "KATA_SN60_PROXY_IMAGE_DIGEST"
PROXY_CONTAINER_ENV = "KATA_SN60_PROXY_CONTAINER"

DEFAULT_INSPECT_TIMEOUT_SECONDS = 20.0


class ProxyImageError(RuntimeError):
    """The scoring proxy cannot be identified or does not match its pin. Fail closed."""


@dataclass(frozen=True)
class ProxyImageProvenance:
    """What was observed about the running proxy, for the published record."""

    container: str
    image_digest: str
    pinned_digest: str
    sandbox_commit: str
    sandbox_tree_sha256: str
    verified: bool
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "container": self.container,
            "image_digest": self.image_digest,
            "pinned_digest": self.pinned_digest,
            "sandbox_commit": self.sandbox_commit,
            "sandbox_tree_sha256": self.sandbox_tree_sha256,
            "verified": self.verified,
            "reason": self.reason,
        }


def pinned_digest(env: dict[str, str] | None = None) -> str:
    env = dict(os.environ if env is None else env)
    return (env.get(PROXY_IMAGE_DIGEST_ENV) or "").strip()


def proxy_container(env: dict[str, str] | None = None) -> str:
    env = dict(os.environ if env is None else env)
    return (env.get(PROXY_CONTAINER_ENV) or "").strip() or DEFAULT_PROXY_CONTAINER


def _docker_inspect(target: str, *, kind: str, runner=None) -> dict[str, Any]:
    run = runner or subprocess.run
    try:
        completed = run(
            ["docker", kind, "inspect", target, "--format", "{{json .}}"],
            capture_output=True, text=True, check=False,
            timeout=DEFAULT_INSPECT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProxyImageError(f"cannot inspect {kind} {target!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ProxyImageError(f"cannot inspect {kind} {target!r}: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except (ValueError, TypeError) as exc:
        raise ProxyImageError(f"docker {kind} inspect {target!r} returned no JSON object") from exc
    if not isinstance(payload, dict):
        raise ProxyImageError(f"docker {kind} inspect {target!r} returned no JSON object")
    return payload


def running_image_digest(
    *, container: str | None = None, env: dict[str, str] | None = None, runner=None
) -> str:
    """The digest of the image the proxy container is RUNNING.

    Read from the container rather than from the tag: the tag is what a rebuild moves, and the
    question this answers is what is serving the judge right now.
    """
    name = container or proxy_container(env)
    container_info = _docker_inspect(name, kind="container", runner=runner)
    image_digest = str(container_info.get("Image") or "").strip()
    if not image_digest:
        raise ProxyImageError(f"proxy container {name!r} reports no image id")
    return image_digest


def image_labels(digest: str, *, runner=None) -> dict[str, str]:
    """Build-time labels of an image, by digest.

    Kept separate from ``running_image_digest`` so the digest comparison can happen FIRST. A
    rebuild that replaces the tag leaves the old image untagged and eventually unresolvable, so a
    stale container's image often cannot be inspected at all -- and "your proxy is running a
    different image than you pinned" is a far more useful failure than "docker could not inspect
    some digest".
    """
    image_info = _docker_inspect(digest, kind="image", runner=runner)
    labels = (image_info.get("Config") or {}).get("Labels") or {}
    return {str(k): str(v) for k, v in labels.items()}


def verify_proxy_image(
    *,
    expected_sandbox_commit: str,
    expected_tree_sha256: str = "",
    env: dict[str, str] | None = None,
    runner=None,
) -> ProxyImageProvenance:
    """Identify the running proxy and hold it to its pin. Raises ``ProxyImageError`` on mismatch.

    An UNPINNED deployment returns an unverified record rather than raising, so the digest still
    reaches the published result and ``preflight`` can report it. Pinning is what makes it
    enforceable; recording it is what makes an unpinned round auditable after the fact.
    """
    env = dict(os.environ if env is None else env)
    name = proxy_container(env)
    expected = pinned_digest(env)

    try:
        observed = running_image_digest(container=name, env=env, runner=runner)
    except ProxyImageError as exc:
        if expected:
            # Pinned but unreadable is a HARD failure: the deployment asked for this to be checked,
            # so "I could not check" must not pass as "it matched".
            raise
        # Unpinned and unreadable promises nothing, so it records that nothing was checked rather
        # than failing a lane that never asked for the guarantee. That is also what keeps a host
        # with no docker (or no proxy yet) able to run an unpinned round at all.
        return ProxyImageProvenance(
            container=name, image_digest="", pinned_digest="",
            sandbox_commit="", sandbox_tree_sha256="", verified=False,
            reason=f"proxy image not inspected and not pinned: {exc}",
        )

    # The pin comparison FIRST: it is decisive, and it stays readable even when the running
    # container's image has since been replaced and can no longer be inspected at all.
    if expected and observed != expected:
        raise ProxyImageError(
            f"proxy container {name!r} is running image {observed}, but "
            f"{PROXY_IMAGE_DIGEST_ENV} pins {expected}. Refusing to score against an "
            f"unattributable proxy (rebuild with tools/build_proxy_image.py and restart it)."
        )

    labels = image_labels(observed, runner=runner)
    label_commit = labels.get(LABEL_SANDBOX_COMMIT, "")
    label_tree = labels.get(LABEL_TREE_SHA256, "")

    if not expected:
        return ProxyImageProvenance(
            container=name, image_digest=observed, pinned_digest="",
            sandbox_commit=label_commit, sandbox_tree_sha256=label_tree, verified=False,
            reason=f"{PROXY_IMAGE_DIGEST_ENV} is not set; the proxy image is not pinned",
        )
    # The digest proves the image is immutable, never where it came from. The labels do.
    if label_commit != expected_sandbox_commit:
        raise ProxyImageError(
            f"proxy image {observed} declares sandbox commit {label_commit or '(none)'}, but the "
            f"lane is scoring {expected_sandbox_commit}. Rebuild it from the verified tree with "
            f"tools/build_proxy_image.py."
        )
    if expected_tree_sha256 and label_tree != expected_tree_sha256:
        raise ProxyImageError(
            f"proxy image {observed} declares sandbox tree {label_tree or '(none)'}, but the lane "
            f"verified {expected_tree_sha256}. The image was built from different bytes at the "
            f"same commit."
        )
    return ProxyImageProvenance(
        container=name, image_digest=observed, pinned_digest=expected,
        sandbox_commit=label_commit, sandbox_tree_sha256=label_tree, verified=True,
    )


__all__ = [
    "DEFAULT_PROXY_CONTAINER",
    "DEFAULT_PROXY_IMAGE_TAG",
    "LABEL_SANDBOX_COMMIT",
    "LABEL_TREE_SHA256",
    "PROXY_CONTAINER_ENV",
    "PROXY_IMAGE_DIGEST_ENV",
    "ProxyImageError",
    "ProxyImageProvenance",
    "image_labels",
    "running_image_digest",
    "pinned_digest",
    "proxy_container",
    "verify_proxy_image",
]
