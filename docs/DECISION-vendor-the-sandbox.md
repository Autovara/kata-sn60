# Decision: vendor the Bitsec sandbox into this repository

**Status:** adopted, 2026-07-29. Reverses a decision this README previously stated as settled.

## What it used to say

> kata-sn60 never vendors or imports it, so scores stay aligned with the live subnet.

That was one sentence doing two jobs, and only one of them was load-bearing:

- **"never imports it"** — still true, and still the point. The pinned tree is executed
  out-of-process exactly as upstream wrote it. Importing it would mean adapting it, and an adapted
  scorer is a different scorer.
- **"never vendors it"** — this is what changed. Vendoring a tree and importing a tree are separate
  questions, and the sentence conflated them.

## What changed

The sandbox is now `git archive` output at the pinned commit, committed at `sandbox/`, pinned by
`sandbox/SANDBOX_MANIFEST.json`. It was previously a git clone on the deployment host at
`/srv/sandbox`, located through `KATA_SN60_SANDBOX_ROOT`.

Nothing about how it is *used* changed. The lane still runs it out-of-process, still reads
`validator/curated-highs-only-2025-08-08.json`, still honours `--sn60-sandbox-root`,
`KATA_SN60_SANDBOX_ROOT` and `KATA_SN60_SANDBOX_COMMIT`. An operator pointing the lane at a clone
gets the previous behaviour exactly.

## Why

**The lane already claimed to score a specific commit; now it can prove it anywhere.** A clone's
provenance rests on the host's filesystem being what someone believes it is. A vendored tree's rests
on digests that travel with the code and can be checked on a fresh checkout, in CI, and inside an
attested room.

**It matches SN22, which already worked this way.** Two lanes doing the same job two ways meant two
sets of failure modes and no shared machinery.

**The size objection does not survive measurement.** `git archive` at the pin is 109 files and
2.0 MB — smaller than SN22's vendored upstream. The 249 MB on `/srv/sandbox` is untracked working
data that was never part of what gets scored. The benchmark the scorer reads is tracked, so the
vendored tree is complete.

**Licensing permits it.** The sandbox is MIT (Copyright (c) 2023 Opentensor); `LICENSE` travels
inside the vendored tree.

## What had to change with it, and would have been silently wrong otherwise

`resolve_sn60_sandbox_source` established the commit like this:

```python
if (sandbox_root / ".git").exists():
    verify the checked-out commit against the pin      # provenance PROVEN
else:
    resolved_commit = expected_commit                  # provenance ASSERTED
```

The `else` branch was written for unit tests and hermetic mirrors, and it trusts the caller. **A
vendored tree has no `.git`, so it takes that branch too.** Moving the sandbox into this repository
without touching this code would have turned every published result's commit from a verified fact
into an unchecked assertion — while reading like a pure relocation, and while every test passed.

It now has three cases:

| Tree | How the commit is established |
| --- | --- |
| clone (has `.git`) | `git rev-parse HEAD`, compared to the pin — unchanged |
| vendored (has a manifest) | manifest commit compared to the pin, then every file digest verified |
| neither | **refused**, unless `KATA_SN60_ALLOW_UNVERIFIED_SANDBOX=1` is set deliberately |

That escape hatch exists because hermetic mirrors are legitimate. It is opt-in and loudly named so
that *"I could not check"* is not spelled the same way as *"I checked"*. 62 tests in this repository
were relying on the old silent acceptance; they now set it explicitly in `tests/conftest.py`.

Verification is structural and fails closed. A changed file, a missing file, an **extra** file, a
symlink and a path escaping the root are all findings. The extra-file rule is not pedantry: the lane
executes out of this tree, so an unlisted `sitecustomize.py` is code nobody reviewed. It caught a
real case within minutes of being written — `ruff` walked into `sandbox/` and left a `.ruff_cache`
inside the tree, and the manifest refused it.

## Where the machinery lives

`kata.core.tree_snapshot`, in the engine, not here. SN22 already had this logic; a second copy of
security-critical verification that has to agree with the first is the mistake
`kata/core/execution_backend.py` exists to undo, after two byte-identical copies drifted.

## What is deliberately NOT done yet

The deployment registry still records `sn60__bitsec` with `integration_mode: "clone"`. Flipping it
to `"vendor"` is a **release-pipeline** change, not a repository one: `installer/kata_subnets.py`
stages `integration.tree_root` into `/srv/kata-sn60-upstream` for `clone` lanes, and the release
bundle validates that the lane's mode matches the manifest's. Flipping the registry alone would fail
the next bundle validation while changing nothing at runtime.

That flip should happen together with a rebuilt bundle, as its own reviewed change. Until then the
deployed lane keeps using `/srv/sandbox` via `KATA_SN60_SANDBOX_ROOT`, which is why this change is
safe to ship while rounds are running.

## Evidence

A clone at the pin and the vendored tree were compared file for file: 109 files each, identical file
sets, identical contents, and identical provenance — same `sandbox_commit`, same `benchmark_sha256`.
The equivalence and every refusal above are pinned by `tests/test_sn60_vendored_sandbox.py`;
restoring the old fail-open branch fails three of them.
