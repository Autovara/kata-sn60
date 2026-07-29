#!/usr/bin/env python3
"""Build the SN60 scoring proxy image FROM THE VERIFIED VENDORED TREE, and print its digest.

The judge's inference goes through this image, so "which code is answering" is part of the
provenance of every score. Upstream builds it as ``bitsec-proxy:latest`` (``validator/manager.py``)
-- a MUTABLE tag, rebuilt from whatever happens to be on the host, carrying no record of which
scorer revision produced it. Two hosts can serve different code under that one name and nothing
notices.

This tool closes both halves:

* It builds from ``sandbox/validator/proxy`` **only after verifying the vendored tree**, so the
  bytes going into the image are the pinned ones.
* It stamps the sandbox commit and the tree digest into image LABELS, so the built artifact carries
  a checkable claim about which revision it came from rather than an assertion in a runbook.

``kata_sn60.execution.proxy_image`` reads those labels back at challenge time and refuses a proxy
that does not match the tree the lane is scoring against.

Usage::

    python tools/build_proxy_image.py                 # build and print the digest
    python tools/build_proxy_image.py --tag my-proxy  # build under a different local tag

The printed ``KATA_SN60_PROXY_IMAGE_DIGEST`` value is what belongs in the lane's deploy settings.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from kata_sn60 import sandbox_snapshot  # noqa: E402
from kata_sn60.execution.proxy_image import (  # noqa: E402
    DEFAULT_PROXY_IMAGE_TAG,
    LABEL_SANDBOX_COMMIT,
    LABEL_TREE_SHA256,
)


def build(tag: str = DEFAULT_PROXY_IMAGE_TAG) -> str:
    root = sandbox_snapshot.vendored_root()

    # Verify BEFORE building. Building first and verifying after would stamp a provenance label
    # onto an image whose sources were never checked.
    verification = sandbox_snapshot.verify(root)
    if not verification.ok:
        raise SystemExit(
            "refusing to build the proxy from an unverified tree:\n  "
            + "\n  ".join(verification.findings[:20])
        )
    document = sandbox_snapshot.manifest(root)
    commit = str(document["upstream_commit"])
    tree_sha256 = str(document["tree_sha256"])

    command = [
        "docker", "build",
        str(root / "validator" / "proxy"),
        # Upstream's own build passes the loggers package as a named context; the Dockerfile does
        # `COPY --from=loggers`. Both directories are inside the tree just verified.
        "--build-context", f"loggers={root / 'loggers'}",
        "--label", f"{LABEL_SANDBOX_COMMIT}={commit}",
        "--label", f"{LABEL_TREE_SHA256}={tree_sha256}",
        "--tag", tag,
    ]
    print(" ".join(command), file=sys.stderr)
    subprocess.run(command, check=True)

    inspected = subprocess.run(
        ["docker", "image", "inspect", tag, "--format", "{{json .}}"],
        check=True, capture_output=True, text=True,
    )
    image = json.loads(inspected.stdout)
    digest = str(image["Id"])
    labels = image.get("Config", {}).get("Labels") or {}
    if labels.get(LABEL_SANDBOX_COMMIT) != commit or labels.get(LABEL_TREE_SHA256) != tree_sha256:
        raise SystemExit("the built image did not carry the provenance labels it was given")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=DEFAULT_PROXY_IMAGE_TAG)
    args = parser.parse_args()
    digest = build(args.tag)
    print(f"KATA_SN60_PROXY_IMAGE_DIGEST={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
