# kata-sn60 — compete on SN60 (Bitsec)

The SN60 subnet plugin for [Kata](https://github.com/Autovara/kata). Everything specific to SN60 lives here: the task, the agent contract, the screening rules, and how agents are scored. This is the guide for **miners** who want to submit an agent. The generic Kata flow (open a PR, scheduled rounds, king promotion) is documented in [kata](https://github.com/Autovara/kata).

SN60 (Bitsec) is a smart-contract security competition. Your agent is handed a real codebase (Solidity and similar) and must report the **high- and critical-severity vulnerabilities** it finds. The agent that reliably finds the most real bugs across the benchmark becomes the **king**.

> [!TIP]
> **Values you need to seal your inference key (step 3 below):**
> - **Room URL** — `https://d9ca9f9e56bee8d8889066f57dcedbf43fca8c02-8080.dstack-pha-prod9.phala.network`
> - **Measurement** — `1ffde25b18ef0af49b24b3ca3e4f9eb972c156ee6e4ac1f0bbacda7bd164d895`
> - **Providers you can use** — `openrouter`, `chutes`, `akashml`
>
> Your agent pays for its own model calls through one of these providers. These are the current approved room values — re-check here before you seal, since a room redeploy changes them.

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

Your provider key never touches the platform in plaintext. You encrypt it to the sealed room and commit only the ciphertext. Clone [kata-tee-runner](https://github.com/Autovara/kata-tee-runner) and run, using the room URL and measurement from the tip above:

```bash
python kata_seal.py \
  --room https://d9ca9f9e56bee8d8889066f57dcedbf43fca8c02-8080.dstack-pha-prod9.phala.network \
  --provider openrouter \
  --key <your-openrouter-api-key> \
  --bundle submissions/sn60__bitsec/miner/alice-20260716-01 \
  --measurement 1ffde25b18ef0af49b24b3ca3e4f9eb972c156ee6e4ac1f0bbacda7bd164d895
```

This writes a `sealed_inference_key` file into your bundle. The maintainer and validators only ever see ciphertext; your key is decrypted inside the attested room and used only to run your own agent. Pick `--provider` from `openrouter`, `chutes`, or `akashml`, and give the matching key.

### 4. Validate and open the PR

```bash
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/alice-20260716-01
```

Commit only your submission directory (including `sealed_inference_key`), push a branch, and open one PR against the default branch. kata-bot screens it and labels it `kata:pending`; the next round scores it.

## Agent and bundle limits

- One submission directory per PR, and one open PR per contributor at a time.
- The PR may touch only that one directory.
- Required files: `agent.py`, `agent_manifest.json`, `submission.json`, plus `sealed_inference_key` once you seal.
- Extra Python helpers are allowed, but only under a `helpers/` subdirectory.
- Bundle size: at most **16 files**, **128 KiB per file**, and **256 KiB total**. No symlinks.
- `agent.py` must define a **synchronous** `agent_main` that is callable with **no arguments** and returns `{"vulnerabilities": [...]}`.
- Your identity must match: the `<github-username>` in the submission id and the `author` in `submission.json` must both equal the GitHub account that opens the PR.

## Screening

Before a round spends any inference, kata-bot screens your source. There are three outcomes.

**Rejected and closed** (`kata:invalid`) — a hard failure:

- No-op agent — `agent_main` returns an empty `{"vulnerabilities": []}` without analyzing anything.
- A constant, canned report that never reads the project.
- Hardcoded secrets, or any reference to validator-only secrets (`CHUTES_API_KEY`, `KATA_VALIDATOR_API_KEY`).
- Benchmark answer-key leakage — tokens such as `answer_key`, `ground_truth`, `expected_findings`, or `scabench`. Do not embed known answers.
- `agent_main` missing, `async`, or not callable with no arguments; or a Python syntax error.
- A `sealed_inference_key` that is not valid ciphertext (it must decode to at least 32 bytes).
- Wrong identity, a bundle outside the limits above, or an exact/AST-equivalent copy of the current king.

**Held for review** (`kata:review`) — a maintainer checks it before the round runs:

- A near-copy of the current king (highly similar, but not an exact copy).
- Ambiguous benchmark-replay logic.

**Passes** — everything else. General, reusable analysis is fine. An honest agent that happens to find nothing on a project simply scores 0 there; it is not rejected for that.

## How you win (scoring)

A round samples one or more benchmark projects — each is a real codebase with a known set of high/critical vulnerabilities. The king and every candidate are scored on the **same** projects, so results are directly comparable.

- **Replicas.** Each project runs a few times (production uses 3). A project counts as *passed* on a **two-thirds majority** — with 3 runs, 2 must pass. Repeating smooths out model noise.
- **Per project the scorer reports:** true positives (real bugs you found), total expected, precision, F1, and pass/fail. A run that errors out counts as a *failed run* and contributes nothing.
- **Ranking order** — compared top to bottom; the first difference decides:
  1. projects passed
  2. true positives
  3. fewer failed runs
  4. precision
  5. F1
- **You must strictly beat the king** on that order to be promoted. An exact tie keeps the king.
- **The king is re-scored fresh every round.** SN60 scores come from LLM-driven detection plus an LLM judge, so they drift run to run — nothing is cached across rounds, and a candidate always faces a freshly-scored king on the same projects.

In short: find more real high/critical bugs, more reliably, with fewer false positives.

## How your agent runs

Your agent runs inside a Phala sealed room (a hardware-attested TEE). It can reach only the in-room inference gateway — your sealed provider key pays for the calls, and there is no other internet. Timing (protects room capacity, not your model or spend):

| Limit | Value |
| --- | --- |
| One inference call at the gateway | 180 s |
| Your whole agent process | 840 s |

Set your HTTP client timeout a little above 180 s (195 s in the example). The room internals — attestation, the gateway, the sealing tool — are in [kata-tee-runner](https://github.com/Autovara/kata-tee-runner).

## The benchmark and scorer

SN60 scoring is defined by the upstream Bitsec subnet ([`Bitsec-AI/sandbox`](https://github.com/Bitsec-AI/sandbox)), pinned to a reviewed commit and run out-of-process. kata-sn60 never vendors or imports it, so scores stay aligned with the live subnet. Operators bump the pin deliberately after re-review; see `deploy/sn60-runner/` for building and deploying the SN60 runner image.
