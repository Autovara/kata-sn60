"""Fixture agent -- a stand-in for a miner's agent.py.

It reproduces the SN60 agent contract: read config from env, write findings to
REPORT_FILE. A real agent would analyze the problem by calling inference via
INFERENCE_API using INFERENCE_API_KEY. This stub just emits a deterministic finding and
records whether an inference key was delivered into the sealed room.
"""
import json
import os
from pathlib import Path

report_file = os.environ["REPORT_FILE"]
project_key = os.environ.get("PROJECT_KEY", "unknown")
inference_key_present = bool(os.environ.get("INFERENCE_API_KEY"))

report = {
    "project_key": project_key,
    "findings": [
        {"id": "F1", "title": "fixture finding", "severity": "low", "line": 42},
    ],
    "inference_key_present": inference_key_present,
}

Path(report_file).write_text(json.dumps(report))
print(f"fixture agent wrote report for {project_key} (key_present={inference_key_present})")
