# `kata-sn60` public surfaces

## Entry point

`kata.subnets` → `sn60 = "kata_sn60:SN60_BITSEC_PLUGIN"`

Declared in the deployment registry and asserted by `verify-resident-env`.

## Plugin methods the engine calls

`sample_problems`, `run_challenge`, `beats_king`, `preflight`, `capacity_estimate`,
`environment_spec`, `static_screen`, `challenge_result_json`, `scoring_profile`

## Upstream pin — declared in three places

| Location | Role |
| --- | --- |
| deployment registry `upstream_commit` | what every published result claims |
| `KATA_SN60_SANDBOX_COMMIT` | **wins at runtime** |
| `sn60_bitsec.DEFAULT_SANDBOX_COMMIT` | used when neither is set |

They are now checked against each other: `kata_bot.env_verify` refuses an environment pin
contradicting the registry, and `tests/test_upstream_pin_agrees_with_the_registry.py` pins the
default. Before that they agreed only by luck, and editing one would have left the lane scoring a
tree every record named differently.

## Environment variables

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

## Subnet-owned settings

`deploy/settings.json` — `lane_env` (`KATA_SUBNET_BUDGET_TEE_RUNS`), `unit_params`
(`timeout_start_sec` 5400, `round_gap_sec` 180, `requires_docker` true).

## Host requirements

`KATA_SN60_SANDBOX_ROOT` (`/srv/sandbox`) and the Docker socket. The round unit additionally gates on
`ConditionPathExists=/srv/kata-tee-runner/.phala-ready`; when that file is absent systemd **skips the
unit and reports success**, which is indistinguishable from a healthy idle lane unless
`ConditionResult` is checked.
