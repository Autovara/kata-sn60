"""Tests for the real SN60 room profile at its inner Docker boundary."""

from __future__ import annotations

import importlib.util
import json
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
