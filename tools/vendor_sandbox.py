#!/usr/bin/env python3
"""Regenerate or verify the pinned SN60 sandbox manifest.

Two subcommands, and the split is the point:

* ``verify`` runs offline against the vendored tree and is what CI and the trusted installer call.
* ``write`` regenerates ``SANDBOX_MANIFEST.json`` from the tree on disk. It is a DELIBERATE act by a
  reviewer after re-vendoring at a new commit, never something a build does implicitly -- a build
  that regenerates its own pin can never detect drift, because the pin would always describe
  whatever it just found.

Re-vendoring is ``git archive`` at the audited commit, so the tree is exactly the files tracked
there -- no build output, no ``.git``, nothing local:

    git -C <sandbox-clone> archive --format=tar <commit> | tar -x -C sandbox/
    python tools/vendor_sandbox.py write
    python tools/vendor_sandbox.py verify
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kata_sn60 import sandbox_snapshot  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "write"))
    parser.add_argument("--root", default=None, help="Vendored tree (defaults to ./sandbox).")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else sandbox_snapshot.vendored_root()

    if args.action == "write":
        document = sandbox_snapshot.build_manifest(root)
        (root / sandbox_snapshot.MANIFEST_NAME).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"wrote {root / sandbox_snapshot.MANIFEST_NAME}")
        print(f"  commit    {document['upstream_commit']}")
        print(f"  files     {document['file_count']}")
        print(f"  tree      {document['tree_sha256']}")
        return 0

    verification = sandbox_snapshot.verify(root)
    print(f"root       {verification.root}")
    print(f"expected   {verification.expected_tree_sha256}")
    print(f"observed   {verification.observed_tree_sha256}")
    for finding in verification.findings:
        print(f"  FINDING  {finding}")
    print("OK" if verification.ok else "DRIFT")
    return 0 if verification.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
