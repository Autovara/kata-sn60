"""SN60 (Bitsec) TEE job profile: how to fetch + run an SN60 problem inside the sealed room.

Implements the generic ``room.profile.TeeJobProfile`` seam. The bitsec problem is a private GHCR
image; the miner's agent runs against it in a resource-capped container, talking only to the in-room
inference gateway, and writes ``report.json`` (its findings). Sealing, the gateway/sealed network,
attestation, and HTTP are generic-room responsibilities; this file is SN60-specific."""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from room.inference_network import (
    GHCR,
    INF_NET,
    docker,
    ensure_inference_network_once,
    ghcr_login,
    inference_gateway_url,
    start_inference_gateway_once,
)
from room.profile import MinerInferenceCredential, TeeJobResult

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
        credential: MinerInferenceCredential | None = None,
        bundle_root: str | None = None,
        job_id: str,
        bundle_sha256: str,
    ) -> TeeJobResult:
        if project_key == self.fixture_project:
            return self._run_fixture(project_key, job_id)
        if bundle_root is None:
            raise RuntimeError("real SN60 TEE execution requires an extracted candidate bundle")
        return self._run_real(project_key, credential, Path(bundle_root), job_id)

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

    def _prepare_agent(self, bundle_dir: Path):
        """Return (cp_source, container_dest, extra_env) for the agent to run.

        The generic room already bounded, extracted, and credential-bound the miner's candidate
        bundle before calling this profile. This profile only copies that verified directory into
        the isolated problem container.
        """
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
        self,
        project_key: str,
        credential: MinerInferenceCredential | None,
        bundle_dir: Path,
        job_id: str,
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
        # token/call policy. Its signed URL binds the encrypted provider choice.
        start_inference_gateway_once()
        ensure_inference_network_once()

        container_suffix = hashlib.sha256(f"{project_key}:{job_id}".encode()).hexdigest()[:20]
        container = f"kata-sn60-{container_suffix}"
        docker(["rm", "-f", container])
        # No deploy-time key exists. An inference-free agent receives empty inference settings,
        # never an operator-funded fallback. A supplied descriptor is decrypted only by the generic
        # room and its signed route prevents the agent from changing provider selection.
        inference_key = credential.api_key if credential else ""
        inference_api = (
            inference_gateway_url(job_id, credential.provider) if credential is not None else ""
        )
        # The agent talks ONLY to the gateway (sealed net); it carries the miner's own key.
        env_args = [
            "-e",
            f"PROJECT_KEY={project_key}",
            "-e",
            f"INFERENCE_API_KEY={inference_key}",
            "-e",
            f"INFERENCE_API={inference_api}",
        ]
        try:
            with tempfile.TemporaryDirectory() as directory:
                workdir = Path(directory)
                cp_src, cp_dst, extra_env = self._prepare_agent(bundle_dir)
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
