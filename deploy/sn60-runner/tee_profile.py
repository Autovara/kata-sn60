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
from room.profile import (
    CREDENTIAL_FAILURE_ATTESTED_ZERO,
    MinerInferenceCredential,
    TeeJobResult,
    resolve_agent_execution_timeout_seconds,
)

#: The unprivileged uid/gid the miner's agent container runs as.
#:
#: Three places must agree on this: the ``--user`` the agent is started with, the ownership of the
#: output volume it writes its report into, and the ownership of its writable ``/tmp``. They are
#: derived from these constants rather than repeated as literals because a mismatch does not fail
#: loudly -- the agent simply cannot write, the report is never produced, and the run is reported
#: as an agent that "completed without writing report.json".
AGENT_UID = 65532
AGENT_GID = 65532


FIXTURE_AGENT = "/app/fixture_agent.py"


def _docker_error(completed) -> str:
    detail = completed.stderr or completed.stdout or f"docker exited {completed.returncode}"
    return detail.strip()[:500]


def _remove_container(name: str, *, allow_missing: bool = True) -> None:
    removed = docker(["rm", "-f", name])
    if removed.returncode == 0:
        return
    detail = _docker_error(removed)
    if allow_missing and "no such container" in detail.lower():
        return
    raise RuntimeError(f"could not remove SN60 container {name}: {detail}")


def _remove_volume(name: str, *, allow_missing: bool = True) -> None:
    removed = docker(["volume", "rm", "-f", name])
    if removed.returncode == 0:
        return
    detail = _docker_error(removed)
    if allow_missing and "no such volume" in detail.lower():
        return
    raise RuntimeError(f"could not remove SN60 volume {name}: {detail}")


def _cleanup_resources(container: str, staging: str, volumes: tuple[str, ...]) -> None:
    errors = []
    for remove, name in (
        (_remove_container, container),
        (_remove_container, staging),
        *((_remove_volume, volume) for volume in volumes),
    ):
        try:
            remove(name)
        except RuntimeError as exc:
            errors.append(str(exc))
    if errors:
        raise RuntimeError("; ".join(errors))


def _missing_report_error(detail: str) -> bool:
    """Whether ``docker cp`` failed because the agent did not create its report."""

    normalized = detail.lower()
    return (
        "could not find the file /kata_output/report.json" in normalized
        or "stat /kata_output/report.json: no such file or directory" in normalized
    )


def _agent_failure(*, image: str, job_id: str, error: str) -> TeeJobResult:
    """Return a candidate-owned failure that the generic room will bind into its quote."""

    return TeeJobResult(
        report={"success": False, "error": error},
        provenance={
            "profile": "sn60-bitsec-v1",
            "project_image": image,
            "inference_policy": "miner-controlled",
            "job_id": job_id,
        },
    )


class Sn60TeeProfile:
    fixture_project = "fixture-project"
    # The single provider key is supplied and funded by each contestant. A missing, stale, or
    # undecryptable ciphertext is therefore quote-bound evidence for a zero score, not a room
    # infrastructure failure that aborts the duel.
    credential_failure_mode = CREDENTIAL_FAILURE_ATTESTED_ZERO

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
        executor.

        The Docker daemon cannot see paths created inside the runner container, and ``docker cp``
        cannot modify a container whose root filesystem is read-only. The verified bundle therefore
        enters a daemon-managed volume through a staging container that is CREATED AND NEVER
        STARTED, then that volume is mounted read-only into the final agent. The report comes back
        the same way, through a PLAIN local volume the staging container can read after the agent
        exits -- it must not be a tmpfs one, because a tmpfs volume is private to each container
        that mounts it, so the agent's report died with the agent and the copy below always found
        an empty directory,
        preserving the report without giving the untrusted agent an unbounded writable disk.

        The staging container exists because ``docker cp`` addresses a CONTAINER, never a volume,
        and neither copy can go through the agent itself: its bundle mount is ``readonly`` so the
        agent cannot rewrite the bundle it is judged on, and reading the report back out of a
        filesystem the untrusted agent controlled would follow whatever it left at that path.

        It is never started, so the room runs exactly ONE process per replica. A ``created``
        container has no pid and no memory -- it is a daemon-side record holding two volume
        references -- and it does not appear in ``docker ps``. With ``PROJECT_CONCURRENCY=3`` the
        VM therefore shows four running services: three agents and the runner.
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
        staging = container + "-stage"
        bundle_volume = container + "-bundle"
        output_volume = container + "-output"
        volumes = (bundle_volume, output_volume)
        _cleanup_resources(container, staging, volumes)
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
            "-e",
            "REPORT_FILE=/kata_output/report.json",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
        ]
        try:
            with tempfile.TemporaryDirectory() as directory:
                workdir = Path(directory)
                cp_src, cp_dst, extra_env = self._prepare_agent(bundle_dir)
                for k, v in extra_env.items():
                    env_args += ["-e", f"{k}={v}"]

                created_bundle_volume = docker(["volume", "create", bundle_volume])
                if created_bundle_volume.returncode != 0:
                    raise RuntimeError(
                        f"create bundle volume failed: {_docker_error(created_bundle_volume)}"
                    )
                # A PLAIN local volume, deliberately not a tmpfs one.
                #
                # A tmpfs-backed volume is NOT shared between containers: every container that
                # mounts it gets its own empty tmpfs, discarded when that container exits. The
                # agent therefore wrote its report into storage that died with it, and the
                # ``docker cp`` below -- which reads the STAGING container's mount -- saw an empty
                # directory every time. The failure is silent and total: the agent runs, spends the
                # miner's inference budget, returns a valid report, and the run is reported as
                # "completed without writing report.json. Agent exit: 0". Every submission failed
                # this way regardless of its code or the project it was given.
                #
                # The volume is removed in the cleanup below, so the report still does not outlive
                # the job; what changes is only that the two containers now see the same bytes.
                created_output_volume = docker(["volume", "create", output_volume])
                if created_output_volume.returncode != 0:
                    raise RuntimeError(
                        f"create output volume failed: {_docker_error(created_output_volume)}"
                    )
                # Docker creates a fresh volume root-owned and 0755, and the agent runs unprivileged
                # as AGENT_UID -- without this it cannot write the report at all. Done in a throwaway
                # root container because only root may chown, and the agent must not be given that.
                chowned = docker(
                    [
                        "run",
                        "--rm",
                        "--user",
                        "0:0",
                        "--network",
                        "none",
                        "--log-driver",
                        "none",
                        "--mount",
                        f"type=volume,source={output_volume},target=/kata_output",
                        image,
                        "chown",
                        f"{AGENT_UID}:{AGENT_GID}",
                        "/kata_output",
                    ]
                )
                if chowned.returncode != 0:
                    raise RuntimeError(
                        f"prepare output volume failed: {_docker_error(chowned)}"
                    )

                create_staging = docker(
                    [
                        "create",
                        "--name",
                        staging,
                        "--network",
                        "none",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges",
                        "--pids-limit",
                        "16",
                        "--memory",
                        "32m",
                        "--cpus",
                        "0.1",
                        "--log-driver",
                        "none",
                        "--mount",
                        f"type=volume,source={bundle_volume},target={cp_dst}",
                        "--mount",
                        f"type=volume,source={output_volume},target=/kata_output",
                        # NEVER STARTED. This container is a handle on the two volumes, not a
                        # workload: ``docker cp`` only ever addresses a container, so something has
                        # to hold the volumes for the bundle to go in and the report to come out.
                        # Both copies work against a container in ``created`` state, so starting it
                        # bought nothing and cost a process per replica -- with concurrency 3 that
                        # was three ``sleep 86400`` processes, and three extra rows in
                        # ``docker ps``, for work that was already done.
                        #
                        # The command is a no-op that exits immediately rather than a long sleep:
                        # if anything ever does start this container by accident, it should stop
                        # being a container, not become a day-long sleeper.
                        "--entrypoint",
                        "python",
                        image,
                        "-c",
                        "pass",
                    ]
                )
                if create_staging.returncode != 0:
                    raise RuntimeError(
                        f"create staging container failed: {_docker_error(create_staging)}"
                    )
                cp_in = docker(["cp", f"{cp_src}/.", f"{staging}:{cp_dst}"])
                if cp_in.returncode != 0:
                    raise RuntimeError(f"cp agent in failed: {_docker_error(cp_in)}")

                create = docker(
                    [
                        "create",
                        "--name",
                        container,
                        "--network",
                        INF_NET,
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges",
                        "--user",
                        f"{AGENT_UID}:{AGENT_GID}",
                        *env_args,
                        "--memory",
                        "512m",
                        "--cpus",
                        "0.25",
                        "--pids-limit",
                        "64",
                        "--log-driver",
                        "none",
                        "--tmpfs",
                        f"/tmp:rw,noexec,nosuid,size=64m,uid={AGENT_UID},gid={AGENT_GID},mode=700",
                        "--mount",
                        f"type=volume,source={bundle_volume},target={cp_dst},readonly",
                        "--mount",
                        f"type=volume,source={output_volume},target=/kata_output",
                        image,
                    ]
                )
                if create.returncode != 0:
                    raise RuntimeError(f"create failed: {_docker_error(create)}")
                # The generic room setting is a total process safety limit, not
                # a model/token/call/retry policy. It leaves the agent free to
                # use its own miner-funded provider strategy within the job.
                start = docker(
                    ["start", container],
                )
                if start.returncode != 0:
                    raise RuntimeError(f"start failed: {_docker_error(start)}")
                execution_timeout = resolve_agent_execution_timeout_seconds()
                try:
                    wait = docker(
                        ["wait", container],
                        timeout=execution_timeout,
                    )
                except subprocess.TimeoutExpired:
                    return _agent_failure(
                        image=image,
                        job_id=job_id,
                        error=(
                            "Bitsec agent execution timed out after "
                            f"{execution_timeout:g} seconds."
                        ),
                    )
                if wait.returncode != 0:
                    raise RuntimeError(f"wait failed: {_docker_error(wait)}")
                cp_out = docker(
                    ["cp", f"{staging}:/kata_output/report.json", str(workdir / "report.json")]
                )
                if cp_out.returncode != 0:
                    detail = _docker_error(cp_out)
                    if not _missing_report_error(detail):
                        raise RuntimeError(f"copy report out failed: {detail}")
                    return _agent_failure(
                        image=image,
                        job_id=job_id,
                        error=(
                            "Bitsec agent completed without writing report.json. "
                            f"Agent exit: {(wait.stdout or '').strip()[:100]}"
                        ),
                    )
                try:
                    report = json.loads((workdir / "report.json").read_text())
                except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                    report = {
                        "success": False,
                        "error": "Bitsec agent report.json was not valid JSON.",
                    }
                if not isinstance(report, dict):
                    report = {
                        "success": False,
                        "error": "Bitsec agent report.json was not a JSON object.",
                    }
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
            _cleanup_resources(container, staging, volumes)
