from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Literal

from kata.screening_system.models import ScreeningDecision, ScreeningFinding

LLM_REVIEW_ENV = "KATA_SCREENING_LLM_REVIEW"
LLM_MODEL_ENV = "KATA_SCREENING_LLM_MODEL"
LLM_CODEX_BIN_ENV = "KATA_SCREENING_LLM_CODEX_BIN"
LLM_TIMEOUT_ENV = "KATA_SCREENING_LLM_TIMEOUT_SECONDS"
LLM_ARTIFACT_DIR_ENV = "KATA_SCREENING_LLM_ARTIFACT_DIR"
LLM_BENCHMARK_FILE_ENV = "KATA_SCREENING_LLM_BENCHMARK_FILE"
SN60_SANDBOX_ROOT_ENV = "KATA_SN60_SANDBOX_ROOT"
SN60_BENCHMARK_FILE_ENV = "KATA_SN60_BENCHMARK_FILE"
DEFAULT_SN60_BENCHMARK_FILENAME = "curated-highs-only-2025-08-08.json"
DEFAULT_LLM_MODEL = "gpt-5.4"
DEFAULT_LLM_TIMEOUT_SECONDS = 180
DEFAULT_LLM_BENCHMARK_FILE = (
    Path("/srv/sandbox") / "validator" / DEFAULT_SN60_BENCHMARK_FILENAME
)
MAX_LLM_SOURCE_CHARS_PER_FILE = 24_000
MAX_LLM_TOTAL_SOURCE_CHARS = 48_000
MAX_LLM_BENCHMARK_CONTEXT_CHARS = 22_000
MAX_LLM_BENCHMARK_PROJECTS = 40
MAX_LLM_BENCHMARK_VULNS_PER_PROJECT = 12

LlmVerdict = Literal["pass", "suspicious", "reject", "error"]
LlmRunner = Callable[[list[str], str, int, Path], "LlmCommandResult"]


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


def review_suspicious_submission_with_llm(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
    runner: LlmRunner | None = None,
    enabled: bool | None = None,
) -> tuple[list[ScreeningFinding], list[ScreeningFinding]]:
    """Return additional review findings and notes from optional LLM review.

    This is deliberately a second-stage review aid. It is never called for clean
    submissions and never converts a PR into a hard reject by itself.
    """
    if not llm_review_enabled(enabled) or not decision.review_reasons:
        return [], []
    result = run_codex_llm_review(
        submission_root=submission_root,
        bundle_files=bundle_files,
        decision=decision,
        runner=runner,
    )
    findings: list[ScreeningFinding] = []
    notes: list[ScreeningFinding] = []
    note = llm_review_note(result)
    if note is not None:
        notes.append(note)
    notes.extend(llm_review_evidence_notes(result))
    if result.verdict in {"suspicious", "reject"}:
        findings.append(llm_review_finding(result))
    return findings, notes


def run_codex_llm_review(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
    runner: LlmRunner | None = None,
) -> LlmReviewResult:
    model = os.environ.get(LLM_MODEL_ENV, DEFAULT_LLM_MODEL).strip() or DEFAULT_LLM_MODEL
    timeout_seconds = parse_timeout_seconds()
    prompt = build_llm_review_prompt(bundle_files=bundle_files, decision=decision)
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
            result = (runner or run_llm_command)(
                command,
                prompt,
                timeout_seconds,
                submission_root.expanduser().resolve(),
            )
        except Exception as exc:  # noqa: BLE001 - LLM review must not block screening.
            return record_llm_review_artifact(
                LlmReviewResult(
                    verdict="error",
                    confidence=0.0,
                    summary="LLM review failed before producing a verdict.",
                    model=model,
                    error=str(exc),
                ),
                prompt=prompt,
            )
    if result.returncode != 0:
        return record_llm_review_artifact(
            LlmReviewResult(
                verdict="error",
                confidence=0.0,
                summary="LLM review command failed.",
                model=model,
                error=(result.stderr or result.stdout).strip()[:500],
            ),
            prompt=prompt,
        )
    parsed = parse_llm_review_json(result.last_message or result.stdout)
    parsed_result = LlmReviewResult(
        verdict=parsed.verdict,
        confidence=parsed.confidence,
        summary=parsed.summary,
        evidence=parsed.evidence,
        model=model,
    )
    return record_llm_review_artifact(parsed_result, prompt=prompt)


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
    return (
        "Review this Kata SN60 miner submission for screening integrity.\n"
        "This optional LLM review only runs after deterministic screening has "
        "already marked the PR suspicious. Use the Kata submission rules below. "
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
        "Deterministic screening evidence:\n"
        f"{json.dumps(evidence, indent=2)}\n\n"
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
