from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Literal

from kata.screening.models import ScreeningDecision, ScreeningFinding

LLM_REVIEW_ENV = "KATA_SCREENING_LLM_REVIEW"
# Force the LLM review to run even when deterministic screening raised no flag. Set
# per-invocation by the manual ``/kata review`` command (not by automated intake), so
# a maintainer's explicit review always gets an LLM verdict.
LLM_FORCE_REVIEW_ENV = "KATA_SCREENING_FORCE_LLM_REVIEW"
LLM_MODEL_ENV = "KATA_SCREENING_LLM_MODEL"
LLM_CODEX_BIN_ENV = "KATA_SCREENING_LLM_CODEX_BIN"
LLM_TIMEOUT_ENV = "KATA_SCREENING_LLM_TIMEOUT_SECONDS"
LLM_ARTIFACT_DIR_ENV = "KATA_SCREENING_LLM_ARTIFACT_DIR"
# OpenAI-API fallback: used only when the local codex CLI is unreachable (missing
# binary, non-zero exit, timeout, or a cost/service error). The key is read from the
# env var NAMED by LLM_API_KEY_NAME_ENV (default OPENAI_API_KEY), so it can point at a
# different, still-funded account than the one the codex CLI is logged into.
LLM_API_MODEL_ENV = "KATA_SCREENING_LLM_API_MODEL"
LLM_API_KEY_NAME_ENV = "KATA_SCREENING_LLM_API_KEY_ENV"
LLM_API_BASE_ENV = "KATA_SCREENING_LLM_API_BASE"
DEFAULT_LLM_API_KEY_NAME = "OPENAI_API_KEY"
DEFAULT_LLM_API_BASE = "https://api.openai.com/v1"
LLM_BENCHMARK_FILE_ENV = "KATA_SCREENING_LLM_BENCHMARK_FILE"
SN60_SANDBOX_ROOT_ENV = "KATA_SN60_SANDBOX_ROOT"
SN60_BENCHMARK_FILE_ENV = "KATA_SN60_BENCHMARK_FILE"
DEFAULT_SN60_BENCHMARK_FILENAME = "curated-highs-only-2025-08-08.json"
DEFAULT_LLM_MODEL = "gpt-5.4"
DEFAULT_LLM_TIMEOUT_SECONDS = 180
DEFAULT_LLM_BENCHMARK_FILE = Path("/srv/sandbox") / "validator" / DEFAULT_SN60_BENCHMARK_FILENAME
MAX_LLM_SOURCE_CHARS_PER_FILE = 24_000
MAX_LLM_TOTAL_SOURCE_CHARS = 48_000
MAX_LLM_BENCHMARK_CONTEXT_CHARS = 22_000
MAX_LLM_BENCHMARK_PROJECTS = 40
MAX_LLM_BENCHMARK_VULNS_PER_PROJECT = 12

LlmVerdict = Literal["pass", "suspicious", "reject", "error"]
LlmRunner = Callable[[list[str], str, int, Path], "LlmCommandResult"]
# (prompt, model, timeout_seconds) -> raw model text. Raises on any failure.
LlmApiRunner = Callable[[str, str, int], str]


@dataclass(frozen=True)
class LlmEvidence:
    line: int | None = None
    reason: str = ""


@dataclass(frozen=True)
class LlmReviewResult:
    verdict: LlmVerdict
    confidence: float
    summary: str
    evidence: list[LlmEvidence] = field(default_factory=list)
    model: str = DEFAULT_LLM_MODEL
    artifact_path: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class LlmCommandResult:
    returncode: int
    stdout: str
    stderr: str
    last_message: str


def llm_review_enabled(value: bool | None = None) -> bool:
    if value is not None:
        return value
    return os.environ.get(LLM_REVIEW_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def force_llm_review_requested(value: bool | None = None) -> bool:
    """Whether this screening was asked to run the LLM review unconditionally.

    Driven by ``KATA_SCREENING_FORCE_LLM_REVIEW`` (set only by the manual
    ``/kata review`` command), so automated intake keeps its cost-bounded behavior
    of running the LLM only when deterministic screening already flagged the PR.
    """
    if value is not None:
        return value
    return os.environ.get(LLM_FORCE_REVIEW_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def review_suspicious_submission_with_llm(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
    runner: LlmRunner | None = None,
    api_runner: LlmApiRunner | None = None,
    enabled: bool | None = None,
    force: bool | None = None,
) -> tuple[list[ScreeningFinding], list[ScreeningFinding]]:
    """Return additional review findings and notes from optional LLM review.

    Normally a second-stage aid: it runs only when deterministic screening already
    raised a review flag, and never converts a PR into a hard reject by itself. When
    ``force`` is set (the manual ``/kata review`` command), it runs even on an
    otherwise-clean submission -- and if it cannot reach a verdict (both the codex CLI
    and the API fallback fail), it holds the PR for manual review rather than passing
    it, so an errored review is never silently treated as clean.
    """
    forced = force_llm_review_requested(force)
    if not llm_review_enabled(enabled):
        return [], []
    if not decision.review_reasons and not forced:
        return [], []
    result = run_codex_llm_review(
        submission_root=submission_root,
        bundle_files=bundle_files,
        decision=decision,
        runner=runner,
        api_runner=api_runner,
    )
    findings: list[ScreeningFinding] = []
    notes: list[ScreeningFinding] = []
    note = llm_review_note(result)
    if note is not None:
        notes.append(note)
    notes.extend(llm_review_evidence_notes(result))
    if result.verdict in {"suspicious", "reject"}:
        findings.append(llm_review_finding(result))
    elif forced and result.verdict == "error":
        # A maintainer-forced review that could not complete stays in manual review
        # (fail-safe): never auto-pass a PR whose review errored out.
        findings.append(llm_review_finding(result))
    return findings, notes


def run_codex_llm_review(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
    runner: LlmRunner | None = None,
    api_runner: LlmApiRunner | None = None,
) -> LlmReviewResult:
    """Review a suspicious submission, codex CLI first with an OpenAI-API fallback.

    The local codex CLI is always tried first. Only if it fails to produce a verdict
    -- a missing binary, non-zero exit, timeout, or a cost/service error, all of which
    surface as verdict ``error`` -- AND an API key is configured is the OpenAI API
    tried next with the same prompt. The audit artifact is recorded once, for whichever
    attempt is final.
    """
    model = os.environ.get(LLM_MODEL_ENV, DEFAULT_LLM_MODEL).strip() or DEFAULT_LLM_MODEL
    timeout_seconds = parse_timeout_seconds()
    prompt = build_llm_review_prompt(bundle_files=bundle_files, decision=decision)
    cwd = submission_root.expanduser().resolve()

    result = _attempt_codex_llm_review(prompt, model, timeout_seconds, cwd, runner)
    if result.verdict == "error" and resolve_llm_api_key():
        api_result = _attempt_api_llm_review(prompt, model, timeout_seconds, api_runner)
        if api_result.verdict != "error":
            result = api_result
        else:
            result = LlmReviewResult(
                verdict="error",
                confidence=0.0,
                summary="LLM review failed on both the codex CLI and the API fallback.",
                model=api_result.model,
                error=f"codex: {result.error or 'n/a'} | api: {api_result.error or 'n/a'}",
            )
    return record_llm_review_artifact(result, prompt=prompt)


def _attempt_codex_llm_review(
    prompt: str,
    model: str,
    timeout_seconds: int,
    cwd: Path,
    runner: LlmRunner | None,
) -> LlmReviewResult:
    command = [
        os.environ.get(LLM_CODEX_BIN_ENV, "codex"),
        "exec",
        "--model",
        model,
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--ephemeral",
        "--color",
        "never",
        "--output-last-message",
    ]
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", encoding="utf-8") as output_file:
        command.extend([output_file.name, "-"])
        try:
            result = (runner or run_llm_command)(command, prompt, timeout_seconds, cwd)
        except Exception as exc:  # noqa: BLE001 - LLM review must not block screening.
            return LlmReviewResult(
                verdict="error",
                confidence=0.0,
                summary="LLM review failed before producing a verdict.",
                model=model,
                error=str(exc),
            )
    if result.returncode != 0:
        return LlmReviewResult(
            verdict="error",
            confidence=0.0,
            summary="LLM review command failed.",
            model=model,
            error=(result.stderr or result.stdout).strip()[:500],
        )
    parsed = parse_llm_review_json(result.last_message or result.stdout)
    return LlmReviewResult(
        verdict=parsed.verdict,
        confidence=parsed.confidence,
        summary=parsed.summary,
        evidence=parsed.evidence,
        model=model,
    )


def _attempt_api_llm_review(
    prompt: str,
    codex_model: str,
    timeout_seconds: int,
    api_runner: LlmApiRunner | None,
) -> LlmReviewResult:
    api_model = os.environ.get(LLM_API_MODEL_ENV, "").strip() or codex_model
    try:
        content = (api_runner or call_openai_chat_api)(prompt, api_model, timeout_seconds)
    except Exception as exc:  # noqa: BLE001 - LLM review must not block screening.
        return LlmReviewResult(
            verdict="error",
            confidence=0.0,
            summary="LLM API review failed before producing a verdict.",
            model=api_model,
            error=str(exc),
        )
    parsed = parse_llm_review_json(content)
    return LlmReviewResult(
        verdict=parsed.verdict,
        confidence=parsed.confidence,
        summary=parsed.summary,
        evidence=parsed.evidence,
        model=api_model,
    )


def resolve_llm_api_key() -> str:
    """The fallback API key, read from the env var NAMED by
    ``KATA_SCREENING_LLM_API_KEY_ENV`` (default ``OPENAI_API_KEY``). Empty string when
    unset, which disables the fallback."""
    key_env = os.environ.get(LLM_API_KEY_NAME_ENV, "").strip() or DEFAULT_LLM_API_KEY_NAME
    return os.environ.get(key_env, "").strip()


def call_openai_chat_api(prompt: str, model: str, timeout_seconds: int) -> str:
    """POST the review prompt to an OpenAI-compatible chat-completions endpoint and
    return the model's raw text reply. Stdlib-only (urllib); raises on any failure."""
    api_key = resolve_llm_api_key()
    if not api_key:
        raise RuntimeError("no API key configured for LLM review fallback")
    base = (os.environ.get(LLM_API_BASE_ENV, "").strip() or DEFAULT_LLM_API_BASE).rstrip("/")
    body = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": prompt}]}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/chat/completions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"http {exc.code}: {detail}") from exc
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not choices:
        raise RuntimeError("LLM API returned no choices")
    message = (choices[0] or {}).get("message") or {}
    content = str(message.get("content") or "").strip()
    if not content:
        raise RuntimeError("LLM API returned empty content")
    return content


def run_llm_command(
    command: list[str],
    prompt: str,
    timeout_seconds: int,
    cwd: Path,
) -> LlmCommandResult:
    completed = subprocess.run(
        command,
        input=prompt,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    output_path = Path(command[-2])
    try:
        last_message = output_path.read_text(encoding="utf-8")
    except OSError:
        last_message = ""
    return LlmCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        last_message=last_message,
    )


def build_llm_review_prompt(
    *,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
) -> str:
    evidence = [
        {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "reason": finding.reason,
            "evidence": finding.evidence,
        }
        for finding in decision.review_reasons
    ]
    sources = render_source_packet(bundle_files)
    benchmark_context = render_llm_benchmark_context()
    benchmark_section = ""
    if benchmark_context:
        benchmark_section = (
            "Internal production benchmark reference for reviewer use only:\n"
            f"{benchmark_context}\n\n"
            "Use this benchmark reference to recognize exact project IDs, finding "
            "IDs, report titles, copied answer text, or narrow project-family "
            "fingerprints in the submitted source. Do not quote hidden benchmark "
            "answer text back in `summary`; explain the issue using submitted-code "
            "line evidence and plain behavior instead.\n\n"
        )
    if evidence:
        context_line = (
            "This LLM review runs after deterministic screening already marked the "
            "PR suspicious. "
        )
        evidence_line = (
            "Deterministic screening evidence:\n" + json.dumps(evidence, indent=2) + "\n\n"
        )
    else:
        context_line = (
            "A maintainer requested a full integrity review of this submission. "
            "Deterministic screening raised no flag, so judge the submitted source "
            "directly against the rules below. "
        )
        evidence_line = (
            "Deterministic screening evidence: none (maintainer-requested full review).\n\n"
        )
    return (
        "Review this Kata SN60 miner submission for screening integrity.\n"
        f"{context_line}"
        "Use the Kata submission rules below. "
        "Be careful and fair: accept as much honest generic analysis as possible, "
        "but flag clear cheating, replay, copy-cat, or secret-leaking code.\n\n"
        "Kata submission rules:\n"
        "- The miner must be a general vulnerability-analysis agent for unseen "
        "projects, not a prewritten answer bank.\n"
        "- The miner must not hardcode benchmark project IDs, known finding IDs, "
        "known report titles, long answer text, or static benchmark-specific "
        "reports.\n"
        "- The miner must not replay exact project fingerprints to emit canned "
        "findings.\n"
        "- The miner must not copy the current king agent exactly or with only "
        "minor/AST-equivalent changes.\n"
        "- The miner must not use answer-key leakage tokens or validator/provider "
        "secrets such as OPENAI_API_KEY, CHUTES_API_KEY, KATA_VALIDATOR_API_KEY, "
        "expected_findings, ground_truth, answer_key, scabench, or hardsteer.\n"
        "- Weak or low-quality generic analysis is allowed. A generic reusable "
        "detector is allowed even if it finds zero vulnerabilities.\n\n"
        "How to judge:\n"
        "- Deterministic screening evidence is primary. Do not ignore it.\n"
        "- Use `pass` when the suspicious evidence is explainable as generic, "
        "honest analysis.\n"
        "- Use `suspicious` when manual review is needed but cheating is not "
        "conclusive.\n"
        "- Use `reject` only when the source clearly supports benchmark replay, "
        "hardcoding, copy-cat behavior, or secret/answer leakage.\n"
        "- Include short line-specific evidence when possible.\n"
        "- Keep `summary` plain, honest, and easy for a contributor to understand. "
        "One or two sentences is enough. No lawyer fog, no robot lecture.\n"
        "- Evidence should point at the submitted source lines and explain what "
        "the code does. If benchmark matching is the issue, say what kind of "
        "thing matched (project ID, finding ID, title, answer text, or fingerprint) "
        "without dumping the hidden benchmark answer back to the contributor.\n"
        "- Return JSON only; no markdown and no extra commentary.\n\n"
        "Confidence rubric:\n"
        "- 0.00-0.39 = low confidence: weak or ambiguous evidence; do not rely on "
        "the LLM result alone.\n"
        "- 0.40-0.69 = medium confidence: plausible concern, but manual review is "
        "needed before action.\n"
        "- 0.70-0.89 = high confidence: strong source evidence supports the verdict.\n"
        "- 0.90-1.00 = very high confidence: direct, concrete source evidence "
        "supports the verdict.\n"
        "- The confidence must describe how strongly the submitted source supports "
        "your verdict under the Kata rules, not how good the miner is.\n\n"
        "Return this exact JSON shape:\n"
        "{\n"
        '  "verdict": "pass|suspicious|reject",\n'
        '  "confidence": 0.0,\n'
        '  "evidence": [{"line": 0, "reason": "..."}],\n'
        '  "summary": "..."\n'
        "}\n\n"
        f"{evidence_line}"
        f"{benchmark_section}"
        "Submitted source files:\n"
        f"{sources}\n"
    )


def render_llm_benchmark_context() -> str:
    path = resolve_llm_benchmark_file()
    if path is None:
        return ""
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, list):
        return ""
    lines = [
        f"benchmark_file={path}",
        f"benchmark_sha256={sha256(raw.encode('utf-8')).hexdigest()}",
        f"project_count={len(payload)}",
    ]
    for project in payload[:MAX_LLM_BENCHMARK_PROJECTS]:
        if not isinstance(project, dict):
            continue
        project_id = str(project.get("project_id") or "").strip()
        name = str(project.get("name") or "").strip()
        platform = str(project.get("platform") or "").strip()
        lines.append(f"- project_id={project_id}; name={name}; platform={platform}")
        vulnerabilities = project.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities[:MAX_LLM_BENCHMARK_VULNS_PER_PROJECT]:
            if not isinstance(vuln, dict):
                continue
            finding_id = str(vuln.get("finding_id") or "").strip()
            severity = str(vuln.get("severity") or "").strip()
            title = " ".join(str(vuln.get("title") or "").split())
            description = " ".join(str(vuln.get("description") or "").split())
            description = description[:240]
            lines.append(
                "  - "
                f"finding_id={finding_id}; severity={severity}; "
                f"title={title}; description_snippet={description}"
            )
    rendered = "\n".join(lines)
    if len(rendered) > MAX_LLM_BENCHMARK_CONTEXT_CHARS:
        rendered = rendered[:MAX_LLM_BENCHMARK_CONTEXT_CHARS] + "\n# [truncated]\n"
    return rendered


def resolve_llm_benchmark_file() -> Path | None:
    for env_name in (LLM_BENCHMARK_FILE_ENV, SN60_BENCHMARK_FILE_ENV):
        raw = os.environ.get(env_name, "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
    sandbox_root = os.environ.get(SN60_SANDBOX_ROOT_ENV, "").strip()
    if sandbox_root:
        sandbox_benchmark = (
            Path(sandbox_root).expanduser().resolve()
            / "validator"
            / DEFAULT_SN60_BENCHMARK_FILENAME
        )
        if sandbox_benchmark.exists():
            return sandbox_benchmark
    if DEFAULT_LLM_BENCHMARK_FILE.exists():
        return DEFAULT_LLM_BENCHMARK_FILE.resolve()
    return None


def render_source_packet(bundle_files: dict[str, str]) -> str:
    rendered: list[str] = []
    remaining = MAX_LLM_TOTAL_SOURCE_CHARS
    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py") or remaining <= 0:
            continue
        clipped = content[: min(len(content), MAX_LLM_SOURCE_CHARS_PER_FILE, remaining)]
        remaining -= len(clipped)
        suffix = "\n# [truncated]\n" if len(clipped) < len(content) else ""
        rendered.append(f"\n--- {relative_path} ---\n{clipped}{suffix}")
    return "\n".join(rendered)


def parse_llm_review_json(raw_output: str) -> LlmReviewResult:
    payload = parse_json_object(raw_output)
    verdict = str(payload.get("verdict") or "error").strip().lower()
    if verdict not in {"pass", "suspicious", "reject"}:
        verdict = "error"
    confidence = clamp_float(payload.get("confidence"), minimum=0.0, maximum=1.0)
    evidence_payload = payload.get("evidence") if isinstance(payload, dict) else []
    evidence: list[LlmEvidence] = []
    if isinstance(evidence_payload, list):
        for item in evidence_payload:
            if not isinstance(item, dict):
                continue
            evidence.append(
                LlmEvidence(
                    line=parse_line_number(item.get("line")),
                    reason=str(item.get("reason") or "").strip(),
                )
            )
    summary = str(payload.get("summary") or "").strip()
    return LlmReviewResult(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary=summary or "LLM review produced no summary.",
        evidence=evidence,
    )


def parse_json_object(raw_output: str) -> dict[str, Any]:
    text = raw_output.strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match is None:
            return {
                "verdict": "error",
                "confidence": 0.0,
                "summary": "LLM review did not return JSON.",
                "evidence": [],
            }
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {
                "verdict": "error",
                "confidence": 0.0,
                "summary": "LLM review returned malformed JSON.",
                "evidence": [],
            }
    return payload if isinstance(payload, dict) else {}


def llm_review_finding(result: LlmReviewResult) -> ScreeningFinding:
    summary = result.summary.strip()[:300]
    return ScreeningFinding(
        rule_id=f"llm_review.{result.verdict}",
        severity="review",
        path=None,
        line=None,
        reason=(f"LLM review supports holding this submission for manual review: {summary}"),
        evidence=f"verdict={result.verdict}; confidence={result.confidence:.2f}",
    )


def llm_review_note(result: LlmReviewResult) -> ScreeningFinding | None:
    summary = result.summary.strip()[:300]
    if not summary:
        return None
    parts = [f"LLM review verdict `{result.verdict}` ({result.confidence:.2f})"]
    if result.artifact_path:
        parts.append("artifact saved for maintainer audit")
    if result.error:
        parts.append(f"error `{result.error[:160]}`")
    return ScreeningFinding(
        rule_id="llm_review.result",
        severity="note",
        path=None,
        line=None,
        reason=f"{'; '.join(parts)}: {summary}",
        evidence=f"model={result.model}",
    )


def llm_review_evidence_notes(result: LlmReviewResult) -> list[ScreeningFinding]:
    notes: list[ScreeningFinding] = []
    if result.verdict not in {"suspicious", "reject"}:
        return notes
    for item in result.evidence[:3]:
        reason = sanitize_public_llm_evidence(item.reason)
        if not reason:
            continue
        notes.append(
            ScreeningFinding(
                rule_id=f"llm_review.{result.verdict}.evidence",
                severity="note",
                path="agent.py" if item.line else None,
                line=item.line,
                reason=f"LLM review source evidence: {reason}",
                evidence=f"verdict={result.verdict}; confidence={result.confidence:.2f}",
            )
        )
    return notes


def sanitize_public_llm_evidence(reason: str) -> str:
    text = " ".join(reason.strip().split())
    if not text:
        return ""
    text = text.replace(";", ",")
    text = re.sub(r"`([^`]{120,})`", "`[long snippet omitted]`", text)
    return text[:260]


def record_llm_review_artifact(
    result: LlmReviewResult,
    *,
    prompt: str,
) -> LlmReviewResult:
    artifact_root = os.environ.get(LLM_ARTIFACT_DIR_ENV, "").strip()
    if not artifact_root:
        return result
    root = Path(artifact_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = root / f"llm-review-{timestamp}-{os.getpid()}.json"
    payload = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "result": {
            **asdict(result),
            "artifact_path": None,
        },
        "prompt": prompt,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return LlmReviewResult(
        verdict=result.verdict,
        confidence=result.confidence,
        summary=result.summary,
        evidence=result.evidence,
        model=result.model,
        artifact_path=str(path),
        error=result.error,
    )


def parse_timeout_seconds() -> int:
    raw = os.environ.get(LLM_TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_LLM_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_LLM_TIMEOUT_SECONDS
    return max(1, value)


def parse_line_number(value: object) -> int | None:
    try:
        line = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def clamp_float(value: object, *, minimum: float, maximum: float) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(maximum, number))
