"""Tests for the real SN60 room profile at its inner Docker boundary."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROFILE = (
    Path(__file__).resolve().parents[1] / "deploy" / "sn60-runner" / "tee_profile.py"
)
ROOM = Path(__file__).resolve().parents[2] / "kata-tee-runner"

pytestmark = pytest.mark.skipif(
    not (ROOM / "room").is_dir(),
    reason="kata-tee-runner is not checked out beside this repository",
)


def _load_profile():
    if str(ROOM) not in sys.path:
        sys.path.insert(0, str(ROOM))
    spec = importlib.util.spec_from_file_location("sn60_tee_profile_under_test", PROFILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sn60_declares_credential_failures_as_participant_zeros() -> None:
    profile = _load_profile().Sn60TeeProfile()
    from room.profile import CREDENTIAL_FAILURE_ATTESTED_ZERO, credential_spec_for

    spec = credential_spec_for(profile)
    assert spec.version == 1
    assert spec.credential_failure_mode == CREDENTIAL_FAILURE_ATTESTED_ZERO


def test_real_sn60_agent_container_is_fail_closed_and_resource_bounded(
    monkeypatch, tmp_path: Path
) -> None:
    profile_module = _load_profile()
    digest = "ab" * 32
    project = "project-a"
    image = f"ghcr.io/bitsec-ai/{project}@sha256:{digest}"
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        json.dumps({project: f"sha256:{digest}"}),
    )
    monkeypatch.setattr(profile_module, "ghcr_login", lambda: None)
    monkeypatch.setattr(profile_module, "start_inference_gateway_once", lambda: None)
    monkeypatch.setattr(profile_module, "ensure_inference_network_once", lambda: None)

    calls: list[list[str]] = []

    class Completed:
        def __init__(self, *, stdout: str = ""):
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def fake_docker(args, **_kwargs):
        command = list(args)
        calls.append(command)
        if command[0] == "cp" and ":/kata_output/report.json" in command[1]:
            Path(command[2]).write_text('{"vulnerabilities":[]}', encoding="utf-8")
        if command[0] == "inspect":
            return Completed(stdout=image)
        return Completed()

    monkeypatch.setattr(profile_module, "docker", fake_docker)
    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("print('agent')\n", encoding="utf-8")

    result = profile_module.Sn60TeeProfile().run(
        project_key=project,
        credential=None,
        bundle_root=str(bundle),
        job_id="01" * 16,
        bundle_sha256="cd" * 32,
    )

    create = next(
        command for command in calls if command[0] == "create" and "--read-only" in command
    )
    assert "--read-only" in create
    assert create[create.index("--cap-drop") + 1] == "ALL"
    assert create[create.index("--security-opt") + 1] == "no-new-privileges"
    assert create[create.index("--user") + 1] == "65532:65532"
    assert create[create.index("--pids-limit") + 1] == "64"
    assert any(value.startswith("/tmp:rw,noexec,nosuid") for value in create)
    mounts = [create[index + 1] for index, value in enumerate(create) if value == "--mount"]
    assert any(
        value.startswith("type=volume,source=kata-sn60-")
        and value.endswith(",target=/kata_bundle,readonly")
        for value in mounts
    )
    assert any(
        value.startswith("type=volume,source=kata-sn60-")
        and value.endswith(",target=/kata_output")
        for value in mounts
    )
    assert not any("type=bind" in value for value in mounts)
    assert ["--log-driver", "none"] == (
        create[create.index("--log-driver"):create.index("--log-driver") + 2]
    )
    assert "REPORT_FILE=/kata_output/report.json" in create
    assert any(command[:2] == ["volume", "create"] for command in calls)
    assert any(
        command[:2] == ["cp", f"{bundle}/."]
        and command[2].endswith("-stage:/kata_bundle")
        for command in calls
    )
    assert ["wait", create[create.index("--name") + 1]] in calls
    assert any(
        command[0] == "cp" and command[1].endswith("-stage:/kata_output/report.json")
        for command in calls
    )
    assert result.report == {"vulnerabilities": []}


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("timeout", "execution timed out"),
        ("missing-report", "without writing report.json"),
        ("malformed-report", "was not a JSON object"),
    ],
)
def test_agent_runtime_failures_return_attested_report_payloads(
    monkeypatch, tmp_path: Path, failure: str, message: str
) -> None:
    """Candidate-owned runtime failures become reports; room/Docker failures still raise."""

    profile_module = _load_profile()
    digest = "ab" * 32
    project = "project-a"
    image = f"ghcr.io/bitsec-ai/{project}@sha256:{digest}"
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        json.dumps({project: f"sha256:{digest}"}),
    )
    monkeypatch.setattr(profile_module, "ghcr_login", lambda: None)
    monkeypatch.setattr(profile_module, "start_inference_gateway_once", lambda: None)
    monkeypatch.setattr(profile_module, "ensure_inference_network_once", lambda: None)

    class Completed:
        def __init__(self, returncode=0, *, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_docker(args, **_kwargs):
        command = list(args)
        if command[0] == "wait" and failure == "timeout":
            raise subprocess.TimeoutExpired(command, 840)
        if command[0] == "cp" and ":/kata_output/report.json" in command[1]:
            if failure == "missing-report":
                return Completed(
                    1,
                    stderr=(
                        "Error response from daemon: Could not find the file "
                        "/kata_output/report.json in container"
                    ),
                )
            Path(command[2]).write_text("[]", encoding="utf-8")
        if command[0] == "inspect":
            return Completed(stdout=image)
        return Completed(stdout="1\n" if command[0] == "wait" else "")

    monkeypatch.setattr(profile_module, "docker", fake_docker)
    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("print('agent')\n", encoding="utf-8")

    result = profile_module.Sn60TeeProfile().run(
        project_key=project,
        credential=None,
        bundle_root=str(bundle),
        job_id="01" * 16,
        bundle_sha256="cd" * 32,
    )

    assert result.report["success"] is False
    assert message in result.report["error"]


def test_docker_copy_failure_remains_infrastructure_error(monkeypatch, tmp_path: Path) -> None:
    profile_module = _load_profile()
    digest = "ab" * 32
    project = "project-a"
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON",
        json.dumps({project: f"sha256:{digest}"}),
    )
    monkeypatch.setattr(profile_module, "ghcr_login", lambda: None)
    monkeypatch.setattr(profile_module, "start_inference_gateway_once", lambda: None)
    monkeypatch.setattr(profile_module, "ensure_inference_network_once", lambda: None)

    class Completed:
        def __init__(self, returncode=0, *, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_docker(args, **_kwargs):
        command = list(args)
        if command[0] == "cp" and ":/kata_output/report.json" in command[1]:
            return Completed(1, stderr="Error response from daemon: storage driver unavailable")
        return Completed(stdout="1\n" if command[0] == "wait" else "")

    monkeypatch.setattr(profile_module, "docker", fake_docker)
    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("print('agent')\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="storage driver unavailable"):
        profile_module.Sn60TeeProfile().run(
            project_key=project,
            credential=None,
            bundle_root=str(bundle),
            job_id="01" * 16,
            bundle_sha256="cd" * 32,
        )


def _capture_docker_calls(monkeypatch, tmp_path: Path) -> list[list[str]]:
    """Run one real profile job against a fake daemon and return every docker command issued."""
    profile_module = _load_profile()
    digest = "ab" * 32
    project = "project-a"
    image = f"ghcr.io/bitsec-ai/{project}@sha256:{digest}"
    monkeypatch.setenv(
        "KATA_SN60_TEE_IMAGE_DIGESTS_JSON", json.dumps({project: f"sha256:{digest}"})
    )
    monkeypatch.setattr(profile_module, "ghcr_login", lambda: None)
    monkeypatch.setattr(profile_module, "start_inference_gateway_once", lambda: None)
    monkeypatch.setattr(profile_module, "ensure_inference_network_once", lambda: None)

    calls: list[list[str]] = []

    class Completed:
        def __init__(self, *, stdout: str = ""):
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def fake_docker(args, **_kwargs):
        command = list(args)
        calls.append(command)
        if command[0] == "cp" and ":/kata_output/report.json" in command[1]:
            Path(command[2]).write_text('{"vulnerabilities":[]}', encoding="utf-8")
        if command[0] == "inspect":
            return Completed(stdout=image)
        return Completed()

    monkeypatch.setattr(profile_module, "docker", fake_docker)
    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("print('agent')\n", encoding="utf-8")
    profile_module.Sn60TeeProfile().run(
        project_key=project, credential=None, bundle_root=str(bundle),
        job_id="01" * 16, bundle_sha256="cd" * 32,
    )
    return calls


def test_the_staging_container_is_never_started(monkeypatch, tmp_path: Path) -> None:
    """The staging container is a HANDLE on the two volumes, not a workload.

    ``docker cp`` addresses a container and never a volume, so something has to hold the bundle and
    report volumes -- but both copies work against a container in ``created`` state. Starting it
    bought nothing and cost one ``sleep 86400`` process per replica, so at PROJECT_CONCURRENCY=3
    the VM showed seven running services where the design calls for four.
    """
    calls = _capture_docker_calls(monkeypatch, tmp_path)
    started = [command[1] for command in calls if command[0] == "start"]
    staged = [
        command[command.index("--name") + 1]
        for command in calls
        if command[0] == "create" and "--name" in command
    ]
    staging_names = [name for name in staged if name.endswith("-stage")]
    assert staging_names, "the staging container should still be created"
    # Exactly ONE process per replica: the agent. The staging container is not among them.
    assert len(started) == 1
    assert staging_names[0] not in started


def test_the_staging_container_still_carries_both_volumes(monkeypatch, tmp_path: Path) -> None:
    """Not started is not the same as not needed: it must still hold the bundle volume writable
    (the agent mounts it readonly) and the report volume (the agent's filesystem is not a safe
    place to read the report back from)."""
    calls = _capture_docker_calls(monkeypatch, tmp_path)
    staging = next(
        command for command in calls
        if command[0] == "create" and command[command.index("--name") + 1].endswith("-stage")
    )
    mounts = [command for i, command in enumerate(staging) if staging[i - 1] == "--mount"]
    assert any("kata_output" in mount for mount in mounts)
    assert any("readonly" not in mount and "-bundle" in mount for mount in mounts), mounts
    # And an accidental start must exit immediately rather than sleep for a day.
    assert "86400" not in " ".join(staging)


def test_both_copies_go_through_the_unstarted_staging_container(
    monkeypatch, tmp_path: Path
) -> None:
    """The whole reason it exists: bundle in, report out, neither through the agent."""
    calls = _capture_docker_calls(monkeypatch, tmp_path)
    copies = [command for command in calls if command[0] == "cp"]
    assert len(copies) == 2
    assert all("-stage" in " ".join(command) for command in copies), copies


def test_the_staging_container_is_still_removed(monkeypatch, tmp_path: Path) -> None:
    """A container that is never started is still a container: it must be disposed of, or the VM
    accumulates one dead record per replica."""
    calls = _capture_docker_calls(monkeypatch, tmp_path)
    removed = [command[2] for command in calls if command[:2] == ["rm", "-f"]]
    assert any(name.endswith("-stage") for name in removed), removed
