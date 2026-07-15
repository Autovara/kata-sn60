"""SN60 static bundle screening (benchmark-leak / secret / no-op agent checks).

Split out of the generic ``screening_system/rules.py`` so the platform's rule set stays
subnet-blind; reached through the SN60 plugin's ``static_screen`` seam. Reuses the generic
helpers/patterns that stay in ``rules.py``. Relocates to ``kata-sn60`` in Phase 3.
"""

from __future__ import annotations

import ast
from pathlib import Path

from kata.ast_utils import (
    find_module_async_function_def,
    find_module_function_def,
    function_supports_no_arg_invocation,
)
from kata.screening_system.models import ScreeningFinding, dedupe_findings
from kata.screening_system.python_ast import (
    agent_main_returns_direct_constant_report,
    agent_main_returns_direct_empty_report,
)
from kata.screening_system.rules import SECRET_PATTERN, finding_reasons, reject_finding
from kata.submission_system.bundle import AGENT_ENTRY_FILENAME, SEALED_KEY_FILENAME

BENCHMARK_LEAK_TOKENS = (
    "curated-highs-only",
    "known_solution",
    "known solution",
    "expected_findings",
    "expected findings",
    "expected_vulnerabilities",
    "expected vulnerabilities",
    "ground_truth",
    "ground truth",
    "answer_key",
    "answer key",
    "scabench",
    "hardsteer",
)
VALIDATOR_SECRET_ENV_TOKENS = (
    "CHUTES_API_KEY",
    "KATA_VALIDATOR_API_KEY",
)


def screen_sn60_static_bundle(bundle_files: dict[str, str]) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py"):
            continue
        for token in VALIDATOR_SECRET_ENV_TOKENS:
            if token in content:
                findings.append(
                    reject_finding(
                        "sn60.validator_secret",
                        "SN60 screening rejected a validator secret reference: "
                        f"{relative_path} references `{token}`.",
                        path=relative_path,
                    )
                )
        if SECRET_PATTERN.search(content):
            findings.append(
                reject_finding(
                    "sn60.hardcoded_secret",
                    f"SN60 screening rejected a hardcoded secret token in {relative_path}.",
                    path=relative_path,
                )
            )

    # TEE rounds are miner-paid. A bundle may intentionally be inference-free (the maintained
    # zero-cost baseline is one example), but when a miner supplies a key it must be ciphertext for
    # the room. The runner has no platform-key fallback, so an omitted key can never spend operator
    # funds; inference attempts without one simply receive no usable upstream credential.
    if _tee_execution_enabled():
        sealed_key = str(bundle_files.get(SEALED_KEY_FILENAME) or "").strip()
        if sealed_key:
            try:
                encrypted = bytes.fromhex(sealed_key)
            except ValueError:
                encrypted = b""
            if len(encrypted) < 32:
                findings.append(
                    reject_finding(
                        "sn60.tee_sealed_key_invalid",
                        "sealed_inference_key must be a non-trivial hexadecimal ciphertext for "
                        "the approved TEE room.",
                        path=SEALED_KEY_FILENAME,
                    )
                )

    agent_source = bundle_files.get(AGENT_ENTRY_FILENAME)
    if agent_source is None:
        return findings + [
            reject_finding(
                "sn60.agent_main_missing",
                "Submission agent must define agent_main(...).",
                path=AGENT_ENTRY_FILENAME,
            )
        ]

    try:
        tree = ast.parse(agent_source, filename=AGENT_ENTRY_FILENAME)
    except SyntaxError as exc:
        line_number = exc.lineno or 1
        return findings + [
            reject_finding(
                "sn60.python_syntax",
                f"Submission bundle contains invalid Python syntax in agent.py:{line_number}.",
                path=AGENT_ENTRY_FILENAME,
                line=line_number,
            )
        ]

    agent_main = find_module_function_def(tree, "agent_main")
    if agent_main is None:
        if find_module_async_function_def(tree, "agent_main") is not None:
            findings.append(
                reject_finding(
                    "sn60.agent_main_async",
                    "Submission agent_main must be a synchronous function; the SN60 "
                    "sandbox runner calls agent_main() directly and does not await "
                    "coroutines.",
                    path=AGENT_ENTRY_FILENAME,
                )
            )
        else:
            findings.append(
                reject_finding(
                    "sn60.agent_main_missing",
                    "Submission agent must define agent_main(...).",
                    path=AGENT_ENTRY_FILENAME,
                )
            )
    elif not function_supports_no_arg_invocation(agent_main):
        findings.append(
            reject_finding(
                "sn60.agent_main_args",
                "Submission agent must support no-argument invocation: agent_main().",
                path=AGENT_ENTRY_FILENAME,
                line=agent_main.lineno,
            )
        )
    elif agent_main_returns_direct_empty_report(agent_main):
        findings.append(
            reject_finding(
                "sn60.direct_empty_report",
                "SN60 screening rejected a no-op agent: agent_main returns an empty "
                "`vulnerabilities` list without doing any analysis.",
                path=AGENT_ENTRY_FILENAME,
                line=agent_main.lineno,
            )
        )
    elif agent_main_returns_direct_constant_report(agent_main):
        findings.append(
            reject_finding(
                "sn60.direct_constant_report",
                "SN60 screening rejected a fake agent: agent_main returns a constant "
                "canned vulnerability report without reading project input.",
                path=AGENT_ENTRY_FILENAME,
                line=agent_main.lineno,
            )
        )

    lowered_source = agent_source.lower()
    for token in BENCHMARK_LEAK_TOKENS:
        if token in lowered_source:
            findings.append(
                reject_finding(
                    "sn60.answer_key_token",
                    "SN60 screening rejected benchmark-answer leakage token: "
                    f"`{token}`.",
                    path=AGENT_ENTRY_FILENAME,
                )
            )
    return dedupe_findings(findings)


def _tee_execution_enabled() -> bool:
    import os

    return os.environ.get("KATA_SN60_USE_TEE_ROOM", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def validate_sn60_static_screening(candidate_root: str | Path) -> list[str]:
    from kata.submission_system.bundle import load_bundle_files

    root = Path(candidate_root).expanduser().resolve()
    return finding_reasons(screen_sn60_static_bundle(load_bundle_files(root)))
