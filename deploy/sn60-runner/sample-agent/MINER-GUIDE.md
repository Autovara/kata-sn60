# Kata SN60 — Miner Guide (clear, step by step)

You compete by submitting a security-auditing **agent** to the Kata repo. Rounds run on a
schedule; the best agent becomes the **king**. With the sealed room, you now **pay for your
own agent's AI** (your key stays private) — that adds **one file** to your submission.

---

## Your submission = ONE folder with FOUR files
Path in the repo: `submissions/sn60__bitsec/miner/<your-submission-id>/`
where `<your-submission-id>` = `<your-github-username>-<YYYYMMDD>-NN` (e.g. `alice-20260715-01`).

The four files:
| File | What it is |
|---|---|
| `agent.py` | your agent (must define `agent_main()`) |
| `agent_manifest.json` | `{"schema_version": 1, "runtime": "python", "entrypoint": "agent.py"}` |
| `submission.json` | metadata (see below) — `author` must equal your GitHub username |
| `sealed_inference_key` | **NEW** — your inference key, sealed to the room |

`submission.json`:
```json
{
  "schema_version": 2,
  "subnet_pack": "sn60__bitsec",
  "mode": "miner",
  "submission_id": "alice-20260715-01",
  "created_at": "2026-07-15T00:00:00+00:00",
  "author": "alice",
  "title": "my agent",
  "notes": "short description"
}
```

---

## ONE-TIME setup (do once)

### 1. Get a funded inference key
Sign up with the provider the maintainer specifies (e.g. **AkashML**), add credit, create
an API key (e.g. `akml-...`). **This is what pays for your agent's AI.** Keep it private.

### 2. Seal your key to the room
The maintainer gives you two values: the **room URL** and the **approved compose-hash**.
```bash
pip install eciespy dcap-qvl
python3 kata_seal.py --room https://<ROOM-URL> --key akml-your-key --measurement <COMPOSE-HASH>
```
This verifies the room is genuine and writes a file **`sealed_inference_key`**. Your real
key never leaves your machine — only this sealed file does (it's useless to anyone else).

---

## EACH submission (a pull request)

1. **Fork / branch** the Kata repo (`github.com/Autovara/kata`).
2. **Make your folder:** `submissions/sn60__bitsec/miner/<your-id>/`.
3. **Put the 4 files in it:** your `agent.py` + `agent_manifest.json` + `submission.json` +
   `sealed_inference_key` (from step 2).
   - Scaffold helper: `uv run kata submission init --help` (or just create them by hand).
4. **Validate locally:**
   ```bash
   uv run kata submission validate --path submissions/sn60__bitsec/miner/<your-id>
   ```
5. **Open a PR** to the default branch. It must touch **only** your submission folder, and
   the folder id + `author` must match your GitHub account. **One open PR per person.**
6. The bot screens your PR → labels it `kata:pending`. **Scoring happens in scheduled
   rounds**, not when you open the PR. If your agent beats the king, your PR is merged and
   you become king.

---

## What happens in a round (so you know what to expect)
1. The round locks the pending PRs.
2. Your `agent.py` runs **inside the sealed room** against the secret problems, using **your
   sealed key** to pay for the AI (model is pinned — everyone uses the same one).
3. The room returns your findings + a proof; Kata verifies it and scores your findings.
4. Best score wins the round.

## Notes
- **Your key is safe:** sealed so only the room opens it; the maintainer never sees it.
- **Budget:** put only what you need on the key — each run is capped.
- **If the maintainer redeploys the room**, they publish a new URL + compose-hash → re-run
  `kata_seal.py` and update your `sealed_inference_key`.
- Start from the sample `agent.py` in this folder and improve it (better prompts, prioritize
  risky files, dedupe findings — inference costs your key, so be efficient).
