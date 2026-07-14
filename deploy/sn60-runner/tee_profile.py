"""SN60 (Bitsec) TEE job profile: how to fetch + run an SN60 problem inside the sealed room.

Implements the generic ``room.profile.TeeJobProfile`` seam. The bitsec problem is a private GHCR
image; the miner's agent runs against it in a resource-capped container, talking only to the in-room
relay for inference, and writes ``report.json`` (its findings). Everything generic -- sealing, the
relay/sealed net, attestation, HTTP -- is the room's; only this SN60-specific execution lives here.

This file is SN60-specific and moves to ``kata-sn60`` in T2; for now it rides in the runner repo."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from room.relay_net import (
    GHCR,
    INF_NET,
    RELAY_ALIAS,
    RELAY_PORT,
    docker,
    ensure_relay_net_once,
    ghcr_login,
    start_relay_once,
)
from room.sealing import resolve_inference_key

# Agent the room runs against the real problem. Must define agent_main() (the bitsec harness
# requires it). A real round mounts the miner's submitted agent here.
AGENT_FILE = os.environ.get("AGENT_FILE", "/app/test_agent.py")
FIXTURE_AGENT = "/app/fixture_agent.py"


class Sn60TeeProfile:
    fixture_project = "fixture-project"

    def image(self, project_key: str) -> str:
        return f"{GHCR}/bitsec-ai/{project_key}:latest"

    def run(self, *, project_key: str, sealed_key: str = "", bundle_b64: str = "") -> dict:
        if project_key == self.fixture_project:
            return self._run_fixture(project_key)
        return self._run_real(project_key, sealed_key, bundle_b64)

    def _run_fixture(self, project_key: str) -> dict:
        workdir = Path(tempfile.mkdtemp())
        report_file = workdir / "report.json"
        env = {
            **os.environ,
            "AGENT_FILE": FIXTURE_AGENT,
            "REPORT_FILE": str(report_file),
            "PROJECT_KEY": project_key,
        }
        subprocess.run(
            [sys.executable, FIXTURE_AGENT], env=env, capture_output=True, text=True, timeout=120
        )
        return json.loads(report_file.read_text())

    def _prepare_agent(self, workdir: Path, bundle_b64: str):
        """Return (cp_source, container_dest, extra_env) for the agent to run.

        If the miner's bundle is provided, extract it and run THAT (mounted at /kata_bundle, same
        contract Kata uses). Otherwise fall back to the bundled stub agent -- local tests only.
        """
        if bundle_b64:
            import base64
            import io
            import tarfile

            bundle_dir = workdir / "bundle"
            bundle_dir.mkdir()
            raw = base64.b64decode(bundle_b64)
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                tf.extractall(bundle_dir, filter="data")  # data filter blocks path traversal
            if not (bundle_dir / "agent.py").exists():
                raise RuntimeError("bundle has no agent.py")
            return str(bundle_dir), "/kata_bundle", {
                "AGENT_FILE": "/kata_bundle/agent.py",
                "PYTHONPATH": "/kata_bundle",
            }
        return AGENT_FILE, "/app/agent.py", {}  # stub fallback (harness defaults to /app/agent.py)

    def _run_real(self, project_key: str, sealed_key: str = "", bundle_b64: str = "") -> dict:
        """Pull + run the real bitsec problem image with the MINER'S agent, mirroring the sandbox
        executor. Uses `docker cp` (not a bind mount): with docker-in-the-room the daemon resolves
        bind paths on the host, which can't see the runner's files.
        """
        ghcr_login()
        image = self.image(project_key)
        pull = docker(["pull", image])
        if pull.returncode != 0:
            raise RuntimeError(f"pull {image} failed: {pull.stderr[:400]}")

        # Bring up the in-room relay + sealed network so the agent does real, pinned inference.
        start_relay_once()
        ensure_relay_net_once()

        workdir = Path(tempfile.mkdtemp())
        cp_src, cp_dst, extra_env = self._prepare_agent(workdir, bundle_b64)
        container = f"kata-sn60-{project_key}".lower()[:60]
        docker(["rm", "-f", container])
        inference_key = resolve_inference_key(sealed_key)  # decrypted inside; owner never saw it
        # The agent talks ONLY to the relay (sealed net); the relay carries the miner's key.
        env_args = [
            "-e", f"PROJECT_KEY={project_key}",
            "-e", f"INFERENCE_API_KEY={inference_key}",
            "-e", f"INFERENCE_API=http://{RELAY_ALIAS}:{RELAY_PORT}",
        ]
        for k, v in extra_env.items():
            env_args += ["-e", f"{k}={v}"]
        create = docker([
            "create", "--name", container, "--network", INF_NET, *env_args,
            "--memory", "512m", "--cpus", "0.25", "--pids-limit", "64",
            image,
        ])
        if create.returncode != 0:
            raise RuntimeError(f"create failed: {create.stderr[:400]}")
        try:
            cp_in = docker(["cp", cp_src, f"{container}:{cp_dst}"])
            if cp_in.returncode != 0:
                raise RuntimeError(f"cp agent in failed: {cp_in.stderr[:400]}")
            start = docker(["start", "-a", container], timeout=600)  # -a waits for exit
            cp_out = docker(["cp", f"{container}:/app/report.json", str(workdir / "report.json")])
            if cp_out.returncode != 0:
                raise RuntimeError(
                    f"no report.json. start stderr: {start.stderr[:500]} stdout: {start.stdout[:300]}"
                )
            return json.loads((workdir / "report.json").read_text())
        finally:
            docker(["rm", "-f", container])
