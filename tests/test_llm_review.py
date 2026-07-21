from __future__ import annotations

import json
from pathlib import Path

from kata.screening.models import ScreeningDecision, ScreeningFinding

from kata_sn60 import llm_review
from kata_sn60.llm_review import (
    LlmCommandResult,
    call_openai_chat_api,
    parse_llm_review_json,
    review_suspicious_submission_with_llm,
)


def review_finding() -> ScreeningFinding:
    return ScreeningFinding(
        rule_id="benchmark_replay.project_fingerprint_branch",
        severity="review",
        path="agent.py",
        line=4,
        reason="SN60 screening found benchmark-specific fingerprints.",
        evidence="matched_tokens=3; points=4",
    )


def test_llm_review_invokes_codex_and_adds_review_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("KATA_SCREENING_LLM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    benchmark = tmp_path / "benchmark.json"
    benchmark.write_text(
        json.dumps(
            [
                {
                    "project_id": "benchmark_project_alpha",
                    "name": "Benchmark Alpha",
                    "platform": "test",
                    "vulnerabilities": [
                        {
                            "finding_id": "finding-alpha",
                            "severity": "high",
                            "title": "Alpha replay title",
                            "description": "Alpha hidden answer text.",
                        }
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("KATA_SCREENING_LLM_BENCHMARK_FILE", str(benchmark))
    calls: list[tuple[list[str], str, int, Path]] = []

    def fake_runner(
        command: list[str],
        prompt: str,
        timeout_seconds: int,
        cwd: Path,
    ) -> LlmCommandResult:
        calls.append((command, prompt, timeout_seconds, cwd))
        return LlmCommandResult(
            returncode=0,
            stdout="",
            stderr="",
            last_message=json.dumps(
                {
                    "verdict": "suspicious",
                    "confidence": 0.82,
                    "evidence": [{"line": 4, "reason": "fingerprint branch"}],
                    "summary": "The branch looks benchmark-specific.",
                }
            ),
        )

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={
            "agent.py": "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': []}\n"
        },
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=fake_runner,
    )

    assert len(calls) == 1
    command, prompt, timeout_seconds, cwd = calls[0]
    assert command[:4] == ["codex", "exec", "--model", "gpt-5.4"]
    assert "--sandbox" in command
    assert timeout_seconds == 180
    assert cwd == tmp_path.resolve()
    assert "Return JSON only" in prompt
    assert "runs after deterministic screening already marked the PR suspicious" in prompt
    assert "Use the Kata submission rules below" in prompt
    assert "accept as much honest generic analysis as possible" in prompt
    assert "The miner must not hardcode benchmark project IDs" in prompt
    assert "Weak or low-quality generic analysis is allowed" in prompt
    assert "Confidence rubric:" in prompt
    assert "0.70-0.89 = high confidence" in prompt
    assert "not how good the miner is" in prompt
    assert "Internal production benchmark reference" in prompt
    assert "benchmark_project_alpha" in prompt
    assert "Alpha replay title" in prompt
    assert findings[0].rule_id == "llm_review.suspicious"
    assert findings[0].severity == "review"
    assert notes[0].rule_id == "llm_review.result"
    assert any(note.rule_id == "llm_review.suspicious.evidence" for note in notes)
    assert any(note.line == 4 for note in notes)
    artifacts = list((tmp_path / "artifacts").glob("llm-review-*.json"))
    assert artifacts
    assert "artifact saved for maintainer audit" in notes[0].reason
    assert str(artifacts[0]) not in notes[0].reason


def test_llm_review_is_not_called_for_clean_decision(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.delenv("KATA_SCREENING_FORCE_LLM_REVIEW", raising=False)

    def fail_runner(
        _command: list[str],
        _prompt: str,
        _timeout_seconds: int,
        _cwd: Path,
    ) -> LlmCommandResult:
        raise AssertionError("LLM runner must not be called for clean submissions")

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "def agent_main():\n    return {}\n"},
        decision=ScreeningDecision(status="pass"),
        runner=fail_runner,
    )

    assert findings == []
    assert notes == []


def test_llm_review_failure_adds_note_not_reject(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    # No API key configured -> the codex failure is final, no fallback attempted.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def failing_runner(
        _command: list[str],
        _prompt: str,
        _timeout_seconds: int,
        _cwd: Path,
    ) -> LlmCommandResult:
        return LlmCommandResult(
            returncode=1,
            stdout="",
            stderr="model unavailable",
            last_message="",
        )

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "def agent_main():\n    return {}\n"},
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=failing_runner,
    )

    assert findings == []
    assert notes[0].rule_id == "llm_review.result"
    assert "error" in notes[0].reason


def test_parse_llm_review_json_extracts_json_from_markdown() -> None:
    result = parse_llm_review_json(
        "```json\n"
        '{"verdict":"reject","confidence":1.2,"evidence":[{"line":0,"reason":"x"}],'
        '"summary":"confirmed"}\n'
        "```"
    )

    assert result.verdict == "reject"
    assert result.confidence == 1.0
    assert result.evidence[0].line is None
    assert result.summary == "confirmed"


def test_llm_review_falls_back_to_api_when_codex_unreachable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    api_calls: list[tuple[str, str, int]] = []

    def missing_codex_runner(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        raise FileNotFoundError("[Errno 2] No such file or directory: 'codex'")

    def fake_api(prompt: str, model: str, timeout_seconds: int) -> str:
        api_calls.append((prompt, model, timeout_seconds))
        return (
            '{"verdict":"reject","confidence":0.9,'
            '"evidence":[{"line":12,"reason":"copied king agent"}],'
            '"summary":"source is a copy of the king"}'
        )

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "def agent_main():\n    return {}\n"},
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=missing_codex_runner,
        api_runner=fake_api,
    )

    assert api_calls, "API fallback should be used when codex is unreachable"
    assert any(f.rule_id == "llm_review.reject" for f in findings)
    assert notes[0].rule_id == "llm_review.result"


def test_llm_review_prefers_codex_when_it_succeeds(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def good_codex(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        return LlmCommandResult(
            returncode=0,
            stdout="",
            stderr="",
            last_message=json.dumps(
                {
                    "verdict": "pass",
                    "confidence": 0.8,
                    "evidence": [],
                    "summary": "generic analyzer",
                }
            ),
        )

    def must_not_call(_prompt, _model, _timeout) -> str:
        raise AssertionError("API must not be called when codex succeeds")

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "def agent_main():\n    return {}\n"},
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=good_codex,
        api_runner=must_not_call,
    )

    assert findings == []
    assert "pass" in notes[0].reason


def test_llm_review_no_fallback_without_api_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def missing_codex(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        raise FileNotFoundError("no codex")

    def must_not_call(_prompt, _model, _timeout) -> str:
        raise AssertionError("API must not be called without a configured key")

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "x"},
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=missing_codex,
        api_runner=must_not_call,
    )

    assert findings == []
    assert notes[0].rule_id == "llm_review.result"
    assert "error" in notes[0].reason


def test_llm_review_api_model_override(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("KATA_SCREENING_LLM_API_MODEL", "codex-5.3")
    seen: dict[str, str] = {}

    def missing_codex(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        raise FileNotFoundError("no codex")

    def fake_api(_prompt: str, model: str, _timeout: int) -> str:
        seen["model"] = model
        return '{"verdict":"pass","confidence":0.5,"evidence":[],"summary":"ok"}'

    review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "x"},
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=missing_codex,
        api_runner=fake_api,
    )

    assert seen["model"] == "codex-5.3"


def test_call_openai_chat_api_builds_request_and_parses_content(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-abc")
    captured: dict[str, object] = {}

    class FakeResp:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            return self._data

        def __enter__(self) -> "FakeResp":
            return self

        def __exit__(self, *_a: object) -> bool:
            return False

    def fake_urlopen(request, timeout):  # noqa: ANN001
        captured["url"] = request.full_url
        captured["auth"] = request.headers.get("Authorization")
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        reply = json.dumps({"verdict": "pass", "confidence": 0.5, "summary": "ok", "evidence": []})
        return FakeResp(
            json.dumps({"choices": [{"message": {"content": reply}}]}).encode("utf-8")
        )

    monkeypatch.setattr(llm_review.urllib.request, "urlopen", fake_urlopen)
    content = call_openai_chat_api("PROMPT-TEXT", "gpt-5.4", 30)

    assert captured["url"].endswith("/chat/completions")
    assert captured["auth"] == "Bearer sk-abc"
    assert captured["body"]["model"] == "gpt-5.4"
    assert captured["body"]["messages"][0]["content"] == "PROMPT-TEXT"
    assert "pass" in content


def test_llm_review_forced_runs_on_clean_submission(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("KATA_SCREENING_FORCE_LLM_REVIEW", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def missing_codex(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        raise FileNotFoundError("no codex")

    def fake_api(_prompt: str, _model: str, _timeout: int) -> str:
        return (
            '{"verdict":"suspicious","confidence":0.7,'
            '"evidence":[{"line":3,"reason":"looks copied"}],"summary":"maybe copied"}'
        )

    # Clean decision (no deterministic review reasons), but forced -> LLM runs.
    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "x"},
        decision=ScreeningDecision(status="pass"),
        runner=missing_codex,
        api_runner=fake_api,
    )
    assert any(f.rule_id == "llm_review.suspicious" for f in findings)
    assert notes[0].rule_id == "llm_review.result"


def test_llm_review_forced_pass_adds_no_finding(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("KATA_SCREENING_FORCE_LLM_REVIEW", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def missing_codex(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        raise FileNotFoundError("no codex")

    def fake_api(_prompt: str, _model: str, _timeout: int) -> str:
        return json.dumps(
            {"verdict": "pass", "confidence": 0.9, "evidence": [], "summary": "clean analyzer"}
        )

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "x"},
        decision=ScreeningDecision(status="pass"),
        runner=missing_codex,
        api_runner=fake_api,
    )
    # pass -> no review finding -> screening stays clean -> pending
    assert findings == []
    assert "pass" in notes[0].reason


def test_llm_review_forced_error_keeps_review(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("KATA_SCREENING_FORCE_LLM_REVIEW", "1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)  # no fallback -> error

    def missing_codex(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        raise FileNotFoundError("no codex")

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "x"},
        decision=ScreeningDecision(status="pass"),
        runner=missing_codex,
    )
    # Both codex and API unavailable -> error verdict -> forced -> held for review.
    assert findings and findings[0].rule_id == "llm_review.error"


def test_llm_review_not_forced_skips_clean_submission(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.delenv("KATA_SCREENING_FORCE_LLM_REVIEW", raising=False)

    def must_not_run(_command, _prompt, _timeout, _cwd) -> LlmCommandResult:
        raise AssertionError("LLM must not run on a clean, unforced submission")

    def api_must_not_run(_prompt: str, _model: str, _timeout: int) -> str:
        raise AssertionError("API must not run on a clean, unforced submission")

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "x"},
        decision=ScreeningDecision(status="pass"),
        runner=must_not_run,
        api_runner=api_must_not_run,
    )
    assert findings == []
    assert notes == []


def test_forced_clean_review_prompt_uses_maintainer_framing() -> None:
    prompt = llm_review.build_llm_review_prompt(
        bundle_files={"agent.py": "def agent_main():\n    return {}\n"},
        decision=ScreeningDecision(status="pass"),
    )
    assert "maintainer requested a full integrity review" in prompt
    assert "none (maintainer-requested full review)" in prompt
    assert "Kata submission rules:" in prompt
