"""SN60 (Bitsec) TEE job profile: how to fetch + run an SN60 problem inside the sealed room.

Implements the generic ``room.profile.TeeJobProfile`` seam. The bitsec problem is a private GHCR
image; the miner's agent runs against it in a resource-capped container, talking only to the in-room
inference gateway, and writes ``report.json`` (its findings). Sealing, the gateway/sealed network,
attestation, and HTTP are generic-room responsibilities; this file is SN60-specific.

This file is SN60-specific and moves to ``kata-sn60`` in T2; for now it rides in the runner repo."""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from room.bundle import extract_submission_bundle
from room.inference_network import (
    GHCR,
    INF_NET,
    INFERENCE_GATEWAY_ALIAS,
    INFERENCE_GATEWAY_PORT,
    docker,
    ensure_inference_network_once,
    ghcr_login,
    start_inference_gateway_once,
)
from room.profile import TeeJobResult
from room.sealing import resolve_inference_key

FIXTURE_AGENT = "/app/fixture_agent.py"


class Sn60TeeProfile:
    fixture_project = "fixture-project"

    def image(self, project_key: str) -> str:
        """Return a deployer-approved, immutable private problem image."""
        raw = os.environ.get("KATA_SN60_TEE_IMAGE_DIGESTS_JSON", "").strip()
        try:
            digests = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("KATA_SN60_TEE_IMAGE_DIGESTS_JSON must be a JSON object") from exc
        digest = digests.get(project_key) if isinstance(digests, dict) else None
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise RuntimeError(
                f"no immutable image digest configured for project {project_key!r}; "
                "set KATA_SN60_TEE_IMAGE_DIGESTS_JSON"
            )
        return f"{GHCR}/bitsec-ai/{project_key}@{digest}"

    def run(
        self,
        *,
        project_key: str,
        sealed_key: str = "",
        bundle_b64: str = "",
        job_id: str,
        bundle_sha256: str,
    ) -> TeeJobResult:
        if project_key == self.fixture_project:
            return self._run_fixture(project_key, job_id)
        return self._run_real(project_key, sealed_key, bundle_b64, job_id)

    def _run_fixture(self, project_key: str, job_id: str) -> TeeJobResult:
        with tempfile.TemporaryDirectory() as directory:
            report_file = Path(directory) / "report.json"
            env = {
                **os.environ,
                "AGENT_FILE": FIXTURE_AGENT,
                "REPORT_FILE": str(report_file),
                "PROJECT_KEY": project_key,
            }
            subprocess.run(
                [sys.executable, FIXTURE_AGENT],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            report = json.loads(report_file.read_text())
        return TeeJobResult(
            report=report,
            provenance={
                "profile": "sn60-bitsec-v1",
                "project_image": "fixture@sha256:fake",
                "inference_policy": "fixture",
                "job_id": job_id,
            },
        )

    def _prepare_agent(self, workdir: Path, bundle_b64: str):
        """Return (cp_source, container_dest, extra_env) for the agent to run.

        The room always receives the miner's candidate bundle. Bounded extraction is part of the
        generic runner so a signed request cannot turn into a tar-bomb or traversal attack.
        """
        bundle_dir = workdir / "bundle"
        extract_submission_bundle(bundle_b64, bundle_dir)
        if not (bundle_dir / "agent.py").is_file():
            raise RuntimeError("bundle has no agent.py")
        return (
            str(bundle_dir),
            "/kata_bundle",
            {
                "AGENT_FILE": "/kata_bundle/agent.py",
                "PYTHONPATH": "/kata_bundle",
            },
        )

    def _run_real(
        self, project_key: str, sealed_key: str, bundle_b64: str, job_id: str
    ) -> TeeJobResult:
        """Pull + run the real bitsec problem image with the MINER'S agent, mirroring the sandbox
        executor. Uses `docker cp` (not a bind mount): with docker-in-the-room the daemon resolves
        bind paths on the host, which can't see the runner's files.
        """
        ghcr_login()
        image = self.image(project_key)
        pull = docker(["pull", image])
        if pull.returncode != 0:
            raise RuntimeError(f"pull {image} failed: {pull.stderr[:400]}")

        # Bring up the in-room gateway + sealed network. The gateway forwards the
        # miner's request and decrypted key without imposing a platform model or
        # token/call policy.
        start_inference_gateway_once()
        ensure_inference_network_once()

        container_suffix = hashlib.sha256(f"{project_key}:{job_id}".encode()).hexdigest()[:20]
        container = f"kata-sn60-{container_suffix}"
        docker(["rm", "-f", container])
        # No deploy-time key exists. An inference-free agent may intentionally omit its ciphertext;
        # it receives an empty credential, never an operator-funded fallback.
        inference_key = resolve_inference_key(sealed_key, required=False)
        # The agent talks ONLY to the gateway (sealed net); it carries the miner's key.
        env_args = [
            "-e",
            f"PROJECT_KEY={project_key}",
            "-e",
            f"INFERENCE_API_KEY={inference_key}",
            "-e",
            f"INFERENCE_API=http://{INFERENCE_GATEWAY_ALIAS}:{INFERENCE_GATEWAY_PORT}/j/{job_id}",
        ]
        try:
            with tempfile.TemporaryDirectory() as directory:
                workdir = Path(directory)
                cp_src, cp_dst, extra_env = self._prepare_agent(workdir, bundle_b64)
                for k, v in extra_env.items():
                    env_args += ["-e", f"{k}={v}"]
                create = docker(
                    [
                        "create",
                        "--name",
                        container,
                        "--network",
                        INF_NET,
                        *env_args,
                        "--memory",
                        "512m",
                        "--cpus",
                        "0.25",
                        "--pids-limit",
                        "64",
                        image,
                    ]
                )
                if create.returncode != 0:
                    raise RuntimeError(f"create failed: {create.stderr[:400]}")
                cp_in = docker(["cp", cp_src, f"{container}:{cp_dst}"])
                if cp_in.returncode != 0:
                    raise RuntimeError(f"cp agent in failed: {cp_in.stderr[:400]}")
                start = docker(["start", "-a", container], timeout=600)  # -a waits for exit
                cp_out = docker(
                    ["cp", f"{container}:/app/report.json", str(workdir / "report.json")]
                )
                if cp_out.returncode != 0:
                    raise RuntimeError(
                        "no report.json. "
                        f"start stderr: {start.stderr[:500]} stdout: {start.stdout[:300]}"
                    )
                report = json.loads((workdir / "report.json").read_text())
            digest = docker(
                ["inspect", "--format", "{{index .RepoDigests 0}}", image]
            ).stdout.strip()
            if not digest or not digest.endswith(image.rsplit("@", 1)[1]):
                raise RuntimeError("pulled problem image did not retain its configured digest")
            return TeeJobResult(
                report=report,
                provenance={
                    "profile": "sn60-bitsec-v1",
                    "project_image": digest,
                    "inference_policy": "miner-controlled",
                    "job_id": job_id,
                },
            )
        finally:
            docker(["rm", "-f", container])
