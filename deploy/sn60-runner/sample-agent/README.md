# Sample SN60 miner agent

A working starting-point agent for the Kata SN60 sealed-room competition.

## What's here
- `agent.py` — defines `agent_main()`, finds smart-contract source files, asks the pinned
  model to find vulnerabilities, and returns them. Improve it to win.

## The contract your agent must follow
```python
def agent_main(project_dir=None, inference_api=None) -> dict:
    return {"vulnerabilities": [
        {"title": "...", "severity": "high|medium|low", "file": "...", "line": 1,
         "description": "..."},
        ...
    ]}
```
- The harness runs `agent_main()` against the project's code (`/app/project_code`) and
  scores your findings vs hidden ground truth.
- Call the AI via `POST {inference_api}/inference` with header `x-inference-api-key` and
  body `{"messages": [...], "max_tokens": N}` (no `model` — the relay pins it, paid by
  your sealed key).

## How to submit (two files in your PR)
1. `agent.py` — this file (or your improved version).
2. `sealed_inference_key` — your inference key, sealed to the room:
   ```bash
   pip install eciespy dcap-qvl
   python3 kata_seal.py --room https://<ROOM-URL> --key akml-your-key --measurement <compose-hash>
   ```
   (The maintainer publishes the room URL + approved compose-hash. `kata_seal.py` is in the
   `kata-sn60-runner` tools.)

## Test it locally (optional)
```bash
export INFERENCE_API=https://<some-openai-compatible-endpoint>   # for a real reply
export INFERENCE_API_KEY=your-test-key
python3 agent.py            # runs against ./ or /app/project_code, prints findings JSON
```

## Ideas to improve it (win the competition)
- Better prompts; give the model more context (function signatures, call graph).
- Prioritize risky files (funds movement, access control) — you pay per inference call.
- De-duplicate findings; keep only high-confidence, high-severity ones.
- Multi-file / cross-contract reasoning.
