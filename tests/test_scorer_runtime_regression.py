"""End-to-end regressions for the isolated scorer runtime, against the REAL pinned scorer.

Every other test in this suite fakes ``subprocess.run``. These do not: they build the real frozen
dependency environment from the vendored ``uv.lock``, run upstream's real ``AgentExecutor`` and
``ScaBenchScorerV2`` on a real report, and take a real score out the other end. Only the LLM
provider is stubbed -- through Kata's own judge gateway, so the metering path is exercised too
rather than bypassed.

That distinction is the point. A scorer runtime that is only ever tested against a fake subprocess
proves that Kata builds a command, not that the pinned scorer can run under it. The bugs this
catches -- a tree the scorer cannot import, a workspace it cannot write, a dependency the frozen
lock does not supply -- are invisible to a mock.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer

import pytest

from kata_sn60 import sandbox_snapshot
from kata_sn60.execution.judge_gateway import JudgeBudgetLimits, JudgeGateway
from kata_sn60.execution.scorer_runtime import ScorerRuntime, ScorerRuntimeError
from kata_sn60.sn60_bitsec import (
    Sn60ReplicaContext,
    build_bitsec_evaluation_command,
    default_subprocess_env,
    extract_sn60_evaluation_payload,
    resolve_sn60_sandbox_source,
    sn60_synthetic_ids,
)

#: A benchmark project with exactly one expected finding, so one judge call decides the score.
PROJECT_KEY = "code4rena_cabal-liquid-staking-token_2025_05"

pytestmark = pytest.mark.skipif(
    shutil.which("uv") is None, reason="the real scorer runtime needs uv to build its environment"
)


@pytest.fixture(autouse=True)
def _production_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """These run against the real vendored tree, under production's verification rules."""
    monkeypatch.delenv("KATA_SN60_ALLOW_UNVERIFIED_SANDBOX", raising=False)
    monkeypatch.delenv("KATA_SN60_SANDBOX_ROOT", raising=False)
    monkeypatch.delenv("KATA_SN60_VENDORED_SANDBOX_ROOT", raising=False)


class _StubInference(BaseHTTPRequestHandler):
    """Answers every match query with a confident match, in the scorer's own response schema."""

    def log_message(self, *args: object) -> None:
        return None

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.dumps({
            "id": "stub", "model": "stub-model",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant",
                "content": json.dumps({"found": True, "matching_index": 0, "confidence": 0.95,
                                       "reason": "same root cause", "decision": "match"}),
            }}],
            "usage": {"prompt_tokens": 1200, "completion_tokens": 40,
                      "prompt_tokens_details": {"cached_tokens": 0}},
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def stub_inference():
    server = TCPServer(("127.0.0.1", 0), _StubInference)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _write_report(reports_root: Path, *, findings: int = 2) -> None:
    """A NON-EMPTY report: the empty-report path skips the scorer entirely by design."""
    vulnerabilities = [{
        "id": "F1",
        "title": "LP unstaking burns shares but leaves underlying tokens, distorting the ratio",
        "description": ("Unstaking burns LP shares without transferring out the underlying tokens, "
                        "so the shares-to-tokens ratio is inflated for the remaining holders."),
        "severity": "high", "location": "contracts/LST.sol:120",
    }]
    if findings > 1:
        vulnerabilities.append({
            "id": "F2", "title": "Unrelated rounding nit",
            "description": "Minor rounding in a view function.",
            "severity": "low", "location": "contracts/View.sol:9",
        })
    reports_root.mkdir(parents=True, exist_ok=True)
    (reports_root / "report.json").write_text(
        json.dumps({"success": True, "report": {"vulnerabilities": vulnerabilities}}),
        encoding="utf-8",
    )


def _context(tmp_path: Path, source, *, label: str) -> Sn60ReplicaContext:
    reports_root = tmp_path / label / PROJECT_KEY
    _write_report(reports_root)
    return Sn60ReplicaContext(
        run_id=f"regression-{label}", variant_name="candidate", project_key=PROJECT_KEY,
        replica_index=1, bundle_root=str(tmp_path / label / "bundle"),
        reports_root=str(reports_root), report_path=str(reports_root / "report.json"),
        evaluation_path=str(reports_root / "evaluation.json"), sandbox_source=source,
    )


def _score(runtime: ScorerRuntime, context: Sn60ReplicaContext, source, gateway: JudgeGateway,
           *, label: str) -> dict:
    """One real evaluation through the real scorer, metered by the real gateway."""
    gateway.register_scope(str(sn60_synthetic_ids(context).job_run_id))
    try:
        interpreter = runtime.prepare()
        with runtime.workspace(label) as workspace:
            completed = subprocess.run(
                build_bitsec_evaluation_command(context, python_executable=str(interpreter)),
                cwd=str(workspace), capture_output=True, text=True, timeout=900,
                env=runtime.environment(
                    workspace=workspace, interpreter=interpreter, base=default_subprocess_env(),
                    overrides={
                        "VALIDATOR_DIR": str(Path(source.benchmark_file).resolve().parent),
                        "CHUTES_API_KEY": "cpk_regression", "PROXY_URL": gateway.url,
                    },
                ),
            )
    finally:
        gateway.unregister_scope(str(sn60_synthetic_ids(context).job_run_id))
    assert completed.returncode == 0, completed.stderr[-2000:]
    payload = extract_sn60_evaluation_payload(completed.stdout)
    assert payload is not None, completed.stdout[-2000:]
    return payload


@pytest.fixture
def source():
    root = sandbox_snapshot.vendored_root()
    return resolve_sn60_sandbox_source(sandbox_root=str(root), scorer_version="ScaBenchScorerV2")


# --- 1. a real non-empty evaluation --------------------------------------------------------------


def test_a_real_nonempty_evaluation_produces_a_real_score(tmp_path, source, stub_inference):
    runtime = ScorerRuntime.for_challenge(source_root=Path(source.sandbox_root),
                                          challenge_root=tmp_path)
    with runtime, JudgeGateway(upstream_url=stub_inference,
                               limits=JudgeBudgetLimits(max_calls=50)) as gateway:
        payload = _score(runtime, _context(tmp_path, source, label="a"), source, gateway, label="a")
        usage = gateway.usage()

    assert payload["status"] == "success"
    result = payload["result"]
    assert result["project"] == PROJECT_KEY
    assert result["total_expected"] == 1
    assert result["total_found"] == 2
    assert result["true_positives"] == 1          # the judge matched the real finding
    assert result["detection_rate"] == 1.0
    assert result["precision"] == 0.5             # one of the two reported findings was spurious
    # The judge call really went through Kata's meter, not around it.
    assert usage.calls == 1
    assert usage.input_tokens == 1200
    assert usage.refusals == 0 and usage.protocol_errors == 0


# --- 2. the verified source is unchanged AFTER a completed evaluation ----------------------------


def test_the_verified_source_is_unchanged_after_a_completed_evaluation(
    tmp_path, source, stub_inference
):
    """Stronger than checking the tree before a round. The scorer writes caches, reports and
    bytecode; the question is whether any of it lands in the evidence, and only a real run that has
    actually written those things can answer it."""
    root = sandbox_snapshot.vendored_root()
    before = sandbox_snapshot.verify(root)
    assert before.ok, before.findings

    runtime = ScorerRuntime.for_challenge(source_root=root, challenge_root=tmp_path)
    with runtime, JudgeGateway(upstream_url=stub_inference,
                               limits=JudgeBudgetLimits(max_calls=50)) as gateway:
        _score(runtime, _context(tmp_path, source, label="b"), source, gateway, label="b")

    after = sandbox_snapshot.verify(root)
    assert after.ok, after.findings
    assert after.observed_tree_sha256 == before.observed_tree_sha256
    assert not (root / ".venv").exists()
    assert not list(root.rglob("__pycache__"))


# --- 3. a second consecutive round succeeds ------------------------------------------------------


def test_a_second_consecutive_round_succeeds(tmp_path, source, stub_inference):
    """The failure this guards is asymmetric: round one leaves the environment, the workspaces and
    the verified tree in whatever state it likes, and round two is the first thing to care."""
    root = sandbox_snapshot.vendored_root()
    scores = []
    for index, label in enumerate(("round1", "round2")):
        runtime = ScorerRuntime.for_challenge(source_root=root, challenge_root=tmp_path / label)
        with runtime, JudgeGateway(upstream_url=stub_inference,
                                   limits=JudgeBudgetLimits(max_calls=50)) as gateway:
            payload = _score(runtime, _context(tmp_path, source, label=label), source, gateway,
                             label=label)
        scores.append(payload["result"]["true_positives"])
        assert sandbox_snapshot.verify(root).ok, f"round {index + 1} damaged the verified tree"
    assert scores == [1, 1]


# --- 4. three concurrent evaluations -------------------------------------------------------------


def test_three_concurrent_evaluations_share_one_environment_without_racing(
    tmp_path, source, stub_inference
):
    """``KATA_SN60_PROJECT_CONCURRENCY`` defaults to 3, so three scorers really do run at once
    against one prepared environment and one gateway. A shared-environment race or a shared
    workspace shows up here and nowhere else."""
    root = sandbox_snapshot.vendored_root()
    runtime = ScorerRuntime.for_challenge(source_root=root, challenge_root=tmp_path)
    labels = ["c1", "c2", "c3"]
    contexts = {label: _context(tmp_path, source, label=label) for label in labels}

    with runtime, JudgeGateway(upstream_url=stub_inference,
                               limits=JudgeBudgetLimits(max_calls=50)) as gateway:
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(_score, runtime, contexts[label], source, gateway, label=label)
                       for label in labels]
            payloads = [future.result() for future in futures]
        usage = gateway.usage()

    assert [p["result"]["true_positives"] for p in payloads] == [1, 1, 1]
    # Each replica made its own judge call and each was attributed; none collided or was refused.
    assert usage.calls == 3
    assert usage.refusals == 0 and usage.protocol_errors == 0
    assert sandbox_snapshot.verify(root).ok


# --- 5. interrupted-challenge recovery -----------------------------------------------------------


def test_an_interrupted_challenge_leaves_nothing_that_breaks_the_next_one(
    tmp_path, source, stub_inference
):
    """A killed round cannot run its cleanup, so it leaves scratch directories behind. The next
    round must neither trip over them nor inherit them -- and, because an abandoned workspace looks
    exactly like a live one, it must not be mistaken for work already done."""
    root = sandbox_snapshot.vendored_root()
    challenge_root = tmp_path / "interrupted"
    runtime = ScorerRuntime.for_challenge(source_root=root, challenge_root=challenge_root)
    runtime.prepare()

    # Simulate the kill: a workspace created and never removed, with junk left in it.
    orphan = runtime.workspace_root / "abandoned-round-r1-deadbeef"
    (orphan / "home").mkdir(parents=True)
    (orphan / "half-written.json").write_text("{", encoding="utf-8")
    assert orphan.exists()

    with runtime, JudgeGateway(upstream_url=stub_inference,
                               limits=JudgeBudgetLimits(max_calls=50)) as gateway:
        payload = _score(runtime, _context(tmp_path, source, label="after"), source, gateway,
                         label="after")

    assert payload["result"]["true_positives"] == 1
    # The runtime's own exit clears the scratch root, orphan included.
    assert not runtime.workspace_root.exists()
    # The durable dependency environment SURVIVES: re-preparing must not rebuild it, or every
    # interrupted round would pay for a fresh sync.
    assert runtime.prepare().exists()
    assert sandbox_snapshot.verify(root).ok


# --- 6. a dependency lock mismatch fails closed --------------------------------------------------


def test_a_dependency_lock_mismatch_fails_closed(tmp_path, stub_inference):
    """``--frozen`` is what makes the environment reproducible. If the lock does not describe the
    project, the honest outcome is a refusal -- resolving fresh dependencies would silently score
    against a different dependency set than the one that was reviewed."""
    mirror = tmp_path / "sandbox"
    shutil.copytree(sandbox_snapshot.vendored_root(), mirror)
    pyproject = mirror / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    # A dependency the pinned uv.lock cannot possibly satisfy.
    assert "dependencies = [" in text
    pyproject.write_text(
        text.replace("dependencies = [", 'dependencies = [\n    "kata-sn60-not-a-real-dep==9.9.9",',
                     1),
        encoding="utf-8",
    )

    runtime = ScorerRuntime(
        source_root=mirror,
        runtime_root=tmp_path / "runtime",
        workspace_root=tmp_path / "workspaces",
    )
    with pytest.raises(ScorerRuntimeError, match="frozen SN60 scorer environment"):
        runtime.prepare()
    # Nothing half-built was published under the fingerprint.
    envs = tmp_path / "runtime" / "envs"
    assert not any(p.is_dir() and not p.name.startswith(".") for p in envs.iterdir())
