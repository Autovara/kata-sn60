# kata-sn60 — compete on SN60 (Bitsec)

The SN60 subnet plugin for [Kata](https://github.com/Autovara/kata). Everything specific to SN60 lives here: the task, the agent contract, the screening rules, and how agents are scored. This is the guide for **miners** who want to submit an agent. The generic Kata flow (open a PR, continuous king-of-the-hill challenges, king promotion) is documented in [kata](https://github.com/Autovara/kata).

SN60 (Bitsec) is a smart-contract security competition. Your agent is handed a real codebase (Solidity and similar) and must report the **high- and critical-severity vulnerabilities** it finds. The agent that reliably finds the most real bugs across the benchmark becomes the **king**.

> [!TIP]
> **Values you need to seal your inference key (step 3 below):**
> - **Room URL** — `https://700196fa6728300af579d0120a91bddda6da0dd2-8080.dstack-pha-prod9.phala.network`
> - **Measurement** — `d3fa361968585622f46a2caa2ba6a75e88489e766020f6283c43f1ccf6121080`
> - **Providers you can use** — `openrouter`, `chutes`, `akashml`
>
> Your agent pays for its own model calls through one of these providers. Do not
> reuse values from an earlier deployment: a room redeploy changes both its
> sealing key and, potentially, its approved measurement.

## Submit an agent

You compete by opening **one** pull request that adds a single agent bundle. The example below uses a miner named `alice`.

### 1. Scaffold the bundle

```bash
uv run kata submission init \
  --subnet-pack sn60__bitsec --mode miner \
  --submission-id alice-20260716-01 \
  --author alice
```

`alice` must be your GitHub username, and the submission id must be `<github-username>-YYYYMMDD-NN`. This creates three files; step 3 adds a fourth, so the bundle you finally commit to the PR has **four**:

```text
submissions/sn60__bitsec/miner/alice-20260716-01/
  agent.py             # your code
  agent_manifest.json  # runtime contract (leave as generated)
  submission.json      # metadata (leave as generated)
  sealed_inference_key # your encrypted provider key — added in step 3
```

### 2. Write `agent.py`

Your entrypoint is `agent_main()`. It must be synchronous, run with no arguments, read the project it is given, and return `{"vulnerabilities": [...]}`. Your agent reaches its model through the room's inference gateway: `POST $INFERENCE_API/inference` with the `x-inference-api-key` header. Here is a minimal working example:

```python
import json, os, urllib.request
from pathlib import Path


def ask_model(prompt: str) -> str:
    endpoint = (os.environ.get("INFERENCE_API") or "").rstrip("/")
    key = os.environ.get("INFERENCE_API_KEY", "")
    body = json.dumps({
        "model": "openai/gpt-4o",  # use a model your chosen provider actually serves
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4000,
    }).encode()
    req = urllib.request.Request(
        endpoint + "/inference", data=body, method="POST",
        headers={"Content-Type": "application/json", "x-inference-api-key": key},
    )
    with urllib.request.urlopen(req, timeout=195) as r:      # keep this near 195s (see timing below)
        return json.loads(r.read())["choices"][0]["message"]["content"]


def agent_main(project_dir=None, inference_api=None) -> dict:
    root = Path(project_dir or os.environ.get("PROJECT_DIR") or "/app/project_code")
    sources = "\n\n".join(
        f"// {p.name}\n{p.read_text(errors='ignore')[:8000]}"
        for p in list(root.rglob("*.sol"))[:8]
    )
    answer = ask_model(
        "Audit these Solidity contracts. Report only exploitable high or critical bugs, "
        'as JSON {"vulnerabilities":[{"title","severity","file","description"}]}.\n\n' + sources
    )
    try:
        return {"vulnerabilities": json.loads(answer).get("vulnerabilities", [])}
    except Exception:
        return {"vulnerabilities": []}
```

Each finding should carry a `title`, a `severity` of `"high"` or `"critical"`, the `file`, and a `description` that explains the bug. Make it a real analyzer, not a template — see screening below.

> [!IMPORTANT]
> Set `model` to something your chosen provider actually serves. A model the provider does not have returns an error, your agent gets no findings, and it scores 0.

### 3. Seal your inference key

Your provider key never touches the platform in plaintext. You encrypt it to the sealed room and commit only the ciphertext. Clone [kata-tee-runner](https://github.com/Autovara/kata-tee-runner) and run:

```bash
read -rsp 'OpenRouter API key: ' OPENROUTER_API_KEY && export OPENROUTER_API_KEY && echo
uv run --extra seal python kata_seal.py \
  --room https://700196fa6728300af579d0120a91bddda6da0dd2-8080.dstack-pha-prod9.phala.network \
  --provider openrouter \
  --key-env OPENROUTER_API_KEY \
  --bundle submissions/sn60__bitsec/miner/alice-20260716-01 \
  --measurement d3fa361968585622f46a2caa2ba6a75e88489e766020f6283c43f1ccf6121080
```

This writes a `sealed_inference_key` file into your bundle. The maintainer and validators only ever see ciphertext; your key is decrypted inside the attested room and used only to run your own agent. Pick `--provider` from `openrouter`, `chutes`, or `akashml`, and give the matching key.

### 4. Validate and open the PR

```bash
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/alice-20260716-01
```

Commit only your submission directory (including `sealed_inference_key`), push a branch, and open one PR against the default branch. kata-bot screens it and labels it `kata:pending`; the next challenge scores it.

## Agent and bundle limits

- One submission directory per PR, and one open PR per contributor at a time.
- The PR may touch only that one directory.
- Required files: `agent.py`, `agent_manifest.json`, `submission.json`, plus `sealed_inference_key` once you seal.
- Extra Python helpers are allowed, but only under a `helpers/` subdirectory.
- Bundle size: at most **16 files**, **128 KiB per file**, and **256 KiB total**. No symlinks.
- `agent.py` must define a **synchronous** `agent_main` that is callable with **no arguments** and returns `{"vulnerabilities": [...]}`.
- Your identity must match: the `<github-username>` in the submission id and the `author` in `submission.json` must both equal the GitHub account that opens the PR.

## Screening

Before a challenge spends any inference, kata-bot screens your source. There are three outcomes.

**Rejected and closed** (`kata:invalid`) — a hard failure:

- No-op agent — `agent_main` returns an empty `{"vulnerabilities": []}` without analyzing anything.
- A constant, canned report that never reads the project.
- Hardcoded secrets, or any reference to validator-only secrets (`CHUTES_API_KEY`, `KATA_VALIDATOR_API_KEY`).
- Benchmark answer-key leakage — tokens such as `answer_key`, `ground_truth`, `expected_findings`, or `scabench`. Do not embed known answers.
- `agent_main` missing, `async`, or not callable with no arguments; or a Python syntax error.
- A `sealed_inference_key` that is not valid ciphertext (it must decode to at least 32 bytes).
- Wrong identity, a bundle outside the limits above, or an exact/AST-equivalent copy of the current king.

**Held for review** (`kata:review`) — a maintainer checks it before the challenge runs:

- A near-copy of the current king (highly similar, but not an exact copy).
- Ambiguous benchmark-replay logic.

**Passes** — everything else. General, reusable analysis is fine. An honest agent that happens to find nothing on a project simply scores 0 there; it is not rejected for that.

## How you win (scoring)

A challenge samples one or more benchmark projects — each is a real codebase with a known set of high/critical vulnerabilities. The king and every candidate are scored on the **same** projects, so results are directly comparable.

- **Replicas.** Each project runs a few times (production uses 3). Its metrics (true positives, precision, F1) are taken **best-of** those runs — your single strongest run counts, so one flaky run won't sink a project — and it counts as *passed* on a **two-thirds majority** (with 3 runs, 2 must pass). Repeating smooths out model noise.
- **Per project the scorer reports:** true positives (real bugs you found), total expected, precision, F1, and pass/fail. A run that errors out counts as a *failed run* and contributes nothing.
- **Ranking order** — your result is compared against the king signal by signal, top to bottom:
  1. **project pass score** — the share of sampled projects you passed (on a two-thirds majority)
  2. **projects passed** — how many projects you passed (a project with at least one passing run)
  3. **true positives** — real high/critical bugs you found
  4. **fewer invalid runs** — the one *reversed* signal: fewer broken/errored runs is better
  5. **precision**
  6. **F1**
- **How the crown moves — the one-sided promotion margin.** You're measured against the king's **running average** over its whole reign (not one run), and each signal has its own **margin**. Reading the signals top to bottom:
  - if you're **behind** the king on a signal → the king keeps the crown (you can't make it up on a lower signal);
  - if you **clearly beat** the king there — by *more than that signal's margin* → you take the crown;
  - if you're **within the margin** → that signal is a tie and the decision moves to the next one.

  So you become king only by **clearly beating the king on some signal (pass score first) without falling behind on a higher one** — a near-tie or a single lucky challenge won't do it, and when you genuinely tie the king near the top, a lower signal (e.g. true positives) decides. Full promotion mechanics live in [kata](https://github.com/Autovara/kata).
- **The king is re-scored fresh every challenge.** SN60 scores come from LLM-driven detection plus an LLM judge, so they drift run to run — nothing is cached across challenges, and a candidate always faces a freshly-scored king on the same projects.

In short: find more real high/critical bugs, more reliably, with fewer false positives.

## How your agent runs

Your agent runs inside a Phala sealed room (a hardware-attested TEE). It can reach only the in-room inference gateway — your sealed provider key pays for the calls, and there is no other internet. Timing (protects room capacity, not your model or spend):

| Limit | Value |
| --- | --- |
| One inference call at the gateway | 180 s |
| Your whole agent process | 840 s |

Set your HTTP client timeout a little above 180 s (195 s in the example). The room internals — attestation, the gateway, the sealing tool — are in [kata-tee-runner](https://github.com/Autovara/kata-tee-runner).

## The benchmark and scorer

SN60 scoring is defined by the upstream Bitsec subnet ([`Bitsec-AI/sandbox`](https://github.com/Bitsec-AI/sandbox)), pinned to a reviewed commit and **run out-of-process**. kata-sn60 does not import it; the pinned tree is executed as upstream wrote it, so scores stay aligned with the live subnet.

The tree is **vendored into this repository** at `sandbox/`, produced by `git archive` at the pinned commit and pinned again by `sandbox/SANDBOX_MANIFEST.json` — a per-file digest list plus one digest over the whole tree. It used to be a clone on the deployment host. See [Why the sandbox is vendored](#why-the-sandbox-is-vendored) below for why that changed and what had to change with it.

Re-pinning at a new upstream commit is deliberate, never a side effect of a build:

```bash
git -C <sandbox-clone> archive --format=tar <commit> | tar -x -C sandbox/
uv run python tools/vendor_sandbox.py write     # regenerate the manifest, after review
uv run python tools/vendor_sandbox.py verify    # what CI and smoke run
```

Operators bump the pin deliberately after re-review; see `deploy/sn60-runner/` for building and deploying the SN60 runner image.

## Why the sandbox is vendored

**Status:** adopted, 2026-07-29. Reverses a decision this README previously stated as settled.

### What it used to say

> kata-sn60 never vendors or imports it, so scores stay aligned with the live subnet.

That was one sentence doing two jobs, and only one of them was load-bearing:

- **"never imports it"** — still true, and still the point. The pinned tree is executed
  out-of-process exactly as upstream wrote it. Importing it would mean adapting it, and an adapted
  scorer is a different scorer.
- **"never vendors it"** — this is what changed. Vendoring a tree and importing a tree are separate
  questions, and the sentence conflated them.

### What changed

The sandbox is now `git archive` output at the pinned commit, committed at `sandbox/`, pinned by
`sandbox/SANDBOX_MANIFEST.json`. It was previously a git clone on the deployment host at
`/srv/sandbox`, located through `KATA_SN60_SANDBOX_ROOT`.

Nothing about how it is *used* changed. The lane still runs it out-of-process, still reads
`validator/curated-highs-only-2025-08-08.json`, still honours `--sn60-sandbox-root`,
`KATA_SN60_SANDBOX_ROOT` and `KATA_SN60_SANDBOX_COMMIT`. An operator pointing the lane at a clone
gets the previous behaviour exactly.

### Why

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

### What had to change with it, and would have been silently wrong otherwise

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

### Where the machinery lives

`kata.core.tree_snapshot`, in the engine, not here. SN22 already had this logic; a second copy of
security-critical verification that has to agree with the first is the mistake
`kata/core/execution_backend.py` exists to undo, after two byte-identical copies drifted.

### What is deliberately NOT done yet

The deployment registry still records `sn60__bitsec` with `integration_mode: "clone"`. Flipping it
to `"vendor"` is a **release-pipeline** change, not a repository one: `installer/kata_subnets.py`
stages `integration.tree_root` into `/srv/kata-sn60-upstream` for `clone` lanes, and the release
bundle validates that the lane's mode matches the manifest's. Flipping the registry alone would fail
the next bundle validation while changing nothing at runtime.

That flip should happen together with a rebuilt bundle, as its own reviewed change. Until then the
deployed lane keeps using `/srv/sandbox` via `KATA_SN60_SANDBOX_ROOT`, which is why this change is
safe to ship while rounds are running.

### Evidence

A clone at the pin and the vendored tree were compared file for file: 109 files each, identical file
sets, identical contents, and identical provenance — same `sandbox_commit`, same `benchmark_sha256`.
The equivalence and every refusal above are pinned by `tests/test_sn60_vendored_sandbox.py`;
restoring the old fail-open branch fails three of them.

## Public surfaces

### Entry point

`kata.subnets` → `sn60 = "kata_sn60:SN60_BITSEC_PLUGIN"`

Declared in the deployment registry and asserted by `verify-resident-env`.

### Plugin methods the engine calls

`sample_problems`, `run_challenge`, `beats_king`, `preflight`, `capacity_estimate`,
`environment_spec`, `static_screen`, `challenge_result_json`, `scoring_profile`

### Upstream pin — declared in three places

| Location | Role |
| --- | --- |
| deployment registry `upstream_commit` | what every published result claims |
| `KATA_SN60_SANDBOX_COMMIT` | **wins at runtime** |
| `sn60_bitsec.DEFAULT_SANDBOX_COMMIT` | used when neither is set |

They are now checked against each other: `kata_bot.env_verify` refuses an environment pin
contradicting the registry, and `tests/test_upstream_pin_agrees_with_the_registry.py` pins the
default. Before that they agreed only by luck, and editing one would have left the lane scoring a
tree every record named differently.

### Environment variables

Upstream/benchmark: `KATA_SN60_SANDBOX_ROOT`, `KATA_SN60_SANDBOX_COMMIT`, `KATA_SN60_BENCHMARK_FILE`

Project selection: `KATA_SN60_PROJECT_KEYS`, `_CHALLENGE_FIXED_PROJECT_KEYS`, `_PROJECT_SAMPLE_SIZE`,
`_PROJECT_SAMPLE_SECRET` (secret), `_PROJECT_CONCURRENCY`, `_REPLICAS_PER_PROJECT`,
`_ENABLE_SCREENER_PROJECT`, `_SCREENER_PROJECT_KEY`, `_REQUIRE_RUNNABLE_PROJECT_IMAGES`

Execution: `KATA_SN60_EXECUTION_BACKEND`, `_EXECUTION_TIMEOUT_SECONDS`,
`_EVALUATION_TIMEOUT_SECONDS`, `_SCREENING_EXECUTION_TIMEOUT_SECONDS`, `_PROXY_NETWORK`

Room: `KATA_SN60_ROOM_URL`, `_MEASUREMENTS`, `_MEASUREMENT_REGISTER`, `_HTTP_TIMEOUT_SECONDS`,
`_REQUEST_LIFETIME_SECONDS`, `_MAX_ATTEMPTS`, `_RETRY_BASE_SECONDS`, `_PCCS_URL`,
`_ALLOW_INSECURE_ROOM_URL`, `KATA_ROOM_AUTH_SECRET`

Inner images: `KATA_SN60_TEE_IMAGE_DIGESTS_JSON` — a map of third-party project images by digest.

Screening/LLM review: `KATA_SCREENING_LLM_*`, `KATA_SCREENING_REVIEW_MODE`,
`KATA_SCREENING_STRICT_REPLAY`, `KATA_SCREENING_FORCE_LLM_REVIEW`

`OPENAI_API_KEY` and `CHUTES_API_KEY` reach this lane and only this lane
(`kata_bot.orchestrator._PAID_PROVIDER_ENV`).

### Subnet-owned settings

`deploy/settings.json` — `lane_env` (`KATA_SUBNET_BUDGET_TEE_RUNS`), `unit_params`
(`timeout_start_sec` 5400, `round_gap_sec` 180, `requires_docker` true).

### Host requirements

`KATA_SN60_SANDBOX_ROOT` (`/srv/sandbox`) and the Docker socket. The round unit additionally gates on
`ConditionPathExists=/srv/kata-tee-runner/.phala-ready`; when that file is absent systemd **skips the
unit and reports success**, which is indistinguishable from a healthy idle lane unless
`ConditionResult` is checked.
