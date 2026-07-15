# kata-sn60

The **SN60 (Bitsec)** subnet plugin for the [Kata](../kata) competition platform — smart-contract
vulnerability detection. This is a self-contained subnet repo: everything SN60-specific lives here
(screening, scoring, validation, execution incl. the Phala TEE room, problem sourcing, CLI).

It plugs into the platform via the `kata.subnets` entry point (`pyproject.toml`); the Kata engine
discovers and loads it with no code change. Install it into the engine's environment
(`uv pip install -e .` / `pip install kata-sn60`) and the `sn60_bitsec` lane becomes available.

## Execution policy

Production is TEE-first: without configuration, SN60 selects the Phala sealed-room backend and
requires `KATA_SN60_ROOM_URL`, room authentication, and approved TEE measurements. The miner's
sealed credential is the only credential an agent receives. Local Docker execution is only for
development and must be selected explicitly with `KATA_SN60_EXECUTION_BACKEND=sandbox`.

The upstream sandbox is pinned to commit
`069ae1e2f152370fa97f3397d8a8f8aed5a78539`. A production operator must deliberately provide a
different `--sn60-sandbox-commit` or `KATA_SN60_SANDBOX_COMMIT` after reviewing the new scorer and
benchmark. The TEE runner already requires immutable problem-image digests; do not use the local
development sandbox as a production fallback.

```
kata_sn60/
  plugin.py            implements SubnetPlugin (the plug)
  sn60_bitsec.py       sandbox execution + ScaBench scoring
  promotion.py verify.py screening.py static_screening.py
  benchmark_replay.py llm_review.py sandbox_canary.py   anti-cheat
  evaluate.py cli.py round.py progress.py               duel + CLI + round wiring
  execution/           TEE-room client and execution-backend policy
  validator_system/    challenge · project_selection · screening · inference_gateway
```

Depends on `kata` for the `SubnetPlugin` contract, the registry, and generic screening/promotion
helpers. See `../KATA-REDESIGN-PLAN.md`.

## Sandbox dependency (pinned upstream — do NOT vendor)

SN60 scoring is defined by the **upstream** SN60 subnet repo, [`Bitsec-AI/sandbox`](https://github.com/Bitsec-AI/sandbox).
kata-sn60 consumes it **read-only and out-of-process** — it never imports it and declares no
dependency on it. At runtime the scoring path runs

```
uv run python -c "from validator.executor import AgentExecutor; ...eval_job_run()"   # cwd = $KATA_SN60_SANDBOX_ROOT
```

so `validator.*` resolves against the sandbox's **own** `uv` env (its `uv.lock`/`.venv`) — a
deliberate isolation boundary. **Do not copy the sandbox into this repo:** it is upstream, it
updates (new problems, scorer bumps), and forking it would make scores diverge from the live subnet.

**Pinned coupling** (bump deliberately, only after re-review — keep `deploy.sh` in sync):

| what | value |
|---|---|
| repo | `Bitsec-AI/sandbox` |
| commit | `069ae1e2f152370fa97f3397d8a8f8aed5a78539` ("increment to build 47") |
| benchmark | `validator/curated-highs-only-2025-08-08.json` (sha256 `6e2d67fe…b747c9ae`) |
| location | `$KATA_SN60_SANDBOX_ROOT` (default `<workspace>/sandbox`; deploy uses `/srv/sandbox`) |

**Minimal surface kata-sn60 actually uses** — `validator/{executor,scorer,models/platform,platform_client}.py`,
`config.py`, `loggers/logger.py`, the benchmark JSON, and the sandbox's `uv.lock`/`.venv`/`.git`.
Everything else in the sandbox (`agent_sandbox/`, `projects.json`, `manager.py`, `neurons/`,
`miner/`, `template/`, root Docker/compose) is unused. The `bitsec_proxy` inference-metering
service is built from `sandbox/validator/proxy` **by `deploy.sh`**; kata-sn60 code only speaks HTTP
to the already-running proxy.
