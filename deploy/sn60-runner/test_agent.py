"""Minimal VALID SN60 agent for the /run test.

The bitsec problem image's harness (run_sandbox.py) imports the mounted agent and calls
`agent_main()`, then writes the result to /app/report.json. So a valid agent must define
`agent_main()` returning {"vulnerabilities": [...]}. This stub returns a fixed finding
(ignores the project + inference) -- enough to prove the room runs the real problem
harness end to end. A real round mounts the miner's own agent here.
"""
from __future__ import annotations


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    return {
        "vulnerabilities": [
            {
                "title": "test finding (plumbing check)",
                "severity": "low",
                "file": "example.sol",
                "line": 1,
                "description": "Stub finding proving the sealed-room run produced a report.",
            }
        ]
    }
