# kata-sn60

The **SN60 (Bitsec)** subnet plugin for the [Kata](../kata) competition platform — smart-contract
vulnerability detection. This is a self-contained subnet repo: everything SN60-specific lives here
(screening, scoring, validation, execution incl. the Phala TEE room, problem sourcing, CLI).

It plugs into the platform via the `kata.subnets` entry point (`pyproject.toml`); the Kata engine
discovers and loads it with no code change. Install it into the engine's environment
(`uv pip install -e .` / `pip install kata-sn60`) and the `sn60_bitsec` lane becomes available.

```
kata_sn60/
  plugin.py            implements SubnetPlugin (the plug)
  sn60_bitsec.py       sandbox execution + ScaBench scoring
  promotion.py verify.py screening.py static_screening.py
  benchmark_replay.py llm_review.py sandbox_canary.py   anti-cheat
  evaluate.py cli.py round.py progress.py               duel + CLI + round wiring
  validator_system/    challenge · project_selection · model_relay · tee_room · screening
```

Depends on `kata` for the `SubnetPlugin` contract, the registry, and generic screening/promotion
helpers. See `../KATA-REDESIGN-PLAN.md`.
