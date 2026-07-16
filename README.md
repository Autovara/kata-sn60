# kata-sn60

This is the SN60 (Bitsec) subnet plugin for the [Kata](../kata) competition platform. It holds
everything specific to SN60: the task, the screening rules, the scoring, and the sealed execution.
The generic engine (how a submission becomes a PR, how rounds are run, how a king is promoted) lives
in [`../kata`](../kata) and [`../kata-bot`](../kata-bot); this repo only fills in the SN60 side.

It plugs into the platform through the `kata.subnets` entry point declared in `pyproject.toml`. Install
it into the engine's environment (`uv pip install -e .` or `pip install kata-sn60`) and the
`sn60_bitsec` lane becomes available. The engine discovers it with no code change.

## What SN60 is

SN60 (Bitsec) is a smart-contract vulnerability-detection competition. A benchmark project is a real
codebase (Solidity and similar smart-contract source). An agent reads that source and reports the
high and critical vulnerabilities it finds.

An agent is a Python bundle whose entry point is `agent_main()`. It runs with no arguments, reads the
project source from its environment, and writes a JSON report of this shape:

```json
{"vulnerabilities": [ { "title": "...", "description": "...", "severity": "...", "file": "...", "function": "..." } ]}
```

A scorer then compares those findings against the benchmark's known answers. The agent that reports
the most real vulnerabilities across the sampled projects wins. See [`../kata`](../kata) for the
generic submission bundle format; the rest of this document covers what SN60 adds on top.

## How an agent gets inference

SN60 agents do their own LLM work, and the miner pays for it. The agent never gets a validator key.
Instead the miner seals a provider credential to the sealed execution room ahead of time, and the
agent's inference calls go through the room's gateway, which forwards them to the miner's chosen
provider and model.

Concretely: the miner encrypts `{provider, api_key, bundle_binding}` to the room's attested public
key and commits the ciphertext as the bundle file `sealed_inference_key`. The binding ties that
ciphertext to the exact submission, so a validator cannot pair one miner's ciphertext with a
different agent. Approved providers include `openrouter`, `chutes`, and `akashml`; the operator
configures the exact routes. The room internals (attestation, the gateway, the sealing tool) live in
[`../kata-tee-runner`](../kata-tee-runner); see there and [`../kata`](../kata) for the submission
side.

A bundle may leave out `sealed_inference_key` on purpose. The maintained zero-cost baseline does
this: it makes no funded inference calls. An agent with no key gets empty inference settings, never a
fallback key, so an omitted key can never spend the operator's money.

## The screening gate

Screening runs on the submission source before any scoring, so a cheating or no-op agent is closed
without spending inference. The SN60-specific static rules live in `static_screening.py`
(`screen_sn60_static_bundle`). A finding is either a hard reject or a hold-for-review.

Rejected outright:

- References to validator-only secret environment variables (`CHUTES_API_KEY`,
  `KATA_VALIDATOR_API_KEY`). An honest miner agent has no reason to name the validator's scoring
  secrets.
- Hardcoded secret tokens in any `.py` file.
- A missing or unusable entry point: `agent_main` must be defined, synchronous (the runner calls it
  directly and does not await), and callable with no arguments. An `async def agent_main` is
  rejected.
- A no-op agent whose `agent_main` directly returns an empty `{"vulnerabilities": []}` without doing
  any analysis.
- A fake agent whose `agent_main` directly returns a constant, canned vulnerability report without
  reading the project.
- Benchmark answer-key leak tokens (for example `answer_key`, `ground_truth`, `expected_findings`,
  `curated-highs-only`, `scabench`). These are markers of a copied benchmark answer.
- When TEE execution is on and the bundle does include a `sealed_inference_key`, that key must be a
  non-trivial hex ciphertext (at least 32 bytes decoded). A trivial or non-hex value is rejected. An
  omitted key is allowed, as above.

Held for review instead of rejected (the engine applies a `kata:review` label so a maintainer looks
before the round proceeds):

- Near-copies of the current king. The generic engine (see [`../kata`](../kata)) rejects an exact
  bundle copy or an agent whose `agent.py` is AST-equivalent to the king. A distinct-but-highly-
  similar agent (similarity at or above 0.85) is not rejected; it is held for review.
- Ambiguous benchmark-replay evidence. Concrete, benchmark-specific replay tells (hardcoded project
  IDs, finding IDs, copied answer text, clusters of verbatim source-line probes) are held for
  review, and are promoted to a hard reject only in strict mode. The SN60 rules for this are in
  `benchmark_replay.py` and `screening.py`.

## How scoring works

The benchmark is a pinned JSON snapshot of projects, each with a list of known high/critical
vulnerabilities (see the coupling table below). A round samples one or more of those projects. The
current king and every candidate are scored on the same sampled projects.

Replicas and the project pass. Each sampled project is run more than once. The number of replicas is
set by the operator (`replicas_per_project` in the round config; the code default is 1, and the
production intent is 3). A project counts as passed on a two-thirds majority of its replicas: with 3
replicas, 2 of 3 must pass. Running the same project several times smooths out the run-to-run drift
of LLM output. Replicas of one project are independent and run concurrently
(`KATA_SN60_PROJECT_CONCURRENCY`).

Per-project metrics. For each project the scorer returns the true positives (real vulnerabilities
found), the total expected, the detection rate, precision, F1, and a PASS/FAIL. A replica whose
execution or evaluation failed contributes zero; it never counts as a PASS or inflates the true
positives.

The rank tuple. A variant's rank is a tuple compared left to right (`sn60_variant_rank` in
`validator_system/challenge.py`):

1. pass score = passed projects / total projects
2. codebase pass count (number of projects passed)
3. total true positives
4. fewer invalid runs (failed replicas)
5. precision
6. F1

Strictly beats. A candidate wins only if its tuple is strictly greater than the king's. An exact tie
keeps the king (`evaluate_sn60_promotion`: a candidate rank at or below the king's is not a
promotion). When there is no king to beat (candidate-only recovery mode), a candidate qualifies only
if it found at least one true positive.

Fresh king each round. SN60's score comes from LLM-driven detection plus an LLM judge, so a variant's
score drifts run to run even on the same benchmark. The plugin declares its scoring profile as
`NOISY` for this reason. The king is therefore re-scored fresh every round against the same sampled
projects as the candidates; there is no cross-round cache that would compare a stale king score
against fresh candidates.

Degraded-king safety. Because the king is re-scored live, a transient inference outage could deflate
the king's own bar and let a candidate dethrone it on a fluke. To prevent that, if the king's scoring
run was degraded by infrastructure failures (any invalid or errored replica, or no successful run at
all), the round skips its outcome and leaves the candidates pending for the next round. This guard is
enforced on the merge/label side in [`../kata-bot`](../kata-bot), which reads the king's
`invalid_runs` and `successful_runs` from the round result.

## Execution backends

Production runs each agent inside a per-project problem image in the Phala sealed TEE room. This is
the default (`EnvSpec.execution` is `tee`), so a miner's sealed credential is the only inference
credential its agent can reach. Set `KATA_SN60_EXECUTION_BACKEND=sandbox` to select local Docker
execution instead; that is for development only, never a production fallback. The policy that chooses
the backend is in `execution/policy.py`.

Under the local sandbox backend, untrusted agent code runs on an `--internal` Docker network so it
can reach the inference proxy but not the public internet. The sealed-room internals (attestation,
the gateway, one-time signed requests) live in [`../kata-tee-runner`](../kata-tee-runner); see
`deploy/sn60-runner/` for building and deploying the SN60 runner image.

## Sandbox dependency (pinned upstream, do NOT vendor)

SN60 scoring is defined by the upstream SN60 subnet repo,
[`Bitsec-AI/sandbox`](https://github.com/Bitsec-AI/sandbox). kata-sn60 consumes it read-only and
out-of-process: it never imports it and declares no dependency on it. At scoring time the path runs

```
uv run python -c "from validator.executor import AgentExecutor; ...eval_job_run()"   # cwd = $KATA_SN60_SANDBOX_ROOT
```

so `validator.*` resolves against the sandbox's own `uv` environment (its `uv.lock` / `.venv`), a
deliberate isolation boundary. Do not copy the sandbox into this repo: it is upstream, it updates
(new problems, scorer bumps), and forking it would make scores diverge from the live subnet.

Pinned coupling (bump deliberately, only after re-review, and keep the production deploy script in
sync):

| what | value |
|---|---|
| repo | `Bitsec-AI/sandbox` |
| commit | `069ae1e2f152370fa97f3397d8a8f8aed5a78539` |
| benchmark | `validator/curated-highs-only-2025-08-08.json` |
| location | `$KATA_SN60_SANDBOX_ROOT` (default `<workspace>/sandbox`; deploy uses `/srv/sandbox`) |

The commit is checked against the checked-out sandbox at run time; a mismatch is a hard error. The
benchmark filename is fixed because the pinned scorer reads that exact hardcoded name. The minimal
surface kata-sn60 uses is `validator/{executor,scorer,models/platform,platform_client}.py`,
`config.py`, `loggers/logger.py`, the benchmark JSON, and the sandbox's own `uv.lock` / `.venv` /
`.git`. The validator-only `bitsec_proxy` scoring service is built from `sandbox/validator/proxy` by
the deploy script; miner agents never reach it.

## Module map

```
kata_sn60/
  plugin.py              implements Kata's SubnetPlugin contract (the plug)
  sn60_bitsec.py         sandbox/room execution + ScaBench scoring + duel machinery
  static_screening.py    source-only anti-cheat (no-op, secrets, answer-key tokens)
  benchmark_replay.py    benchmark-replay detection (copied answers)
  screening.py           benchmark-review hook (reject vs review)
  llm_review.py          LLM review of suspicious submissions
  sandbox_canary.py mutation_canary.py   generalization checks
  promotion.py verify.py  promotion provenance + benchmark-currency checks
  king_cache.py          within-round king scoreboard (avoids re-running the king per candidate)
  round.py evaluate.py cli.py progress.py   round wiring + CLI + live progress
  execution/             TEE-room client (tee_room.py) and backend policy (policy.py)
  validator_system/      challenge (scoring/promotion) · project_selection · screening
```

The plugin depends on `kata` for the `SubnetPlugin` contract, the lane registry, and the generic
screening and promotion helpers.
