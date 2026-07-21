"""SN60 static bundle screening for replay, secrets, and no-op agents.

Kata invokes this through the plugin's ``static_screen`` hook; shared structural
checks remain in Kata while benchmark-specific rules live here.
"""

from __future__ import annotations

import ast
from pathlib import Path

from kata.ast_utils import (
    count_module_function_defs,
    find_module_async_function_def,
    find_module_function_def,
    function_supports_no_arg_invocation,
)
from kata.screening.models import ScreeningFinding, dedupe_findings
from kata.screening.python_ast import (
    agent_main_returns_direct_constant_report,
    agent_main_returns_direct_empty_report,
)
from kata.screening.rules import SECRET_PATTERN, finding_reasons, reject_finding
from kata.submissions.bundle import AGENT_ENTRY_FILENAME, SEALED_KEY_FILENAME

from kata_sn60.execution.policy import tee_execution_enabled

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

    # TEE challenges are miner-paid: the agent runs inside the attested room and pays for
    # its own inference with the miner's sealed provider key. A submission with no
    # sealed_inference_key has no inference credential, so it can never produce real
    # findings -- it would only burn one real room job to score 0. Reject it here at
    # static screening (source-only, no inference) instead of admitting it to a challenge.
    # When a key IS supplied it must be non-trivial ciphertext for the room.
    if tee_execution_enabled():
        sealed_key = str(bundle_files.get(SEALED_KEY_FILENAME) or "").strip()
        if not sealed_key:
            findings.append(
                reject_finding(
                    "sn60.tee_sealed_key_missing",
                    "SN60 runs your agent inside an attested TEE where it pays for its own "
                    "model calls, so every submission must include a sealed_inference_key. "
                    "This bundle has none, so the agent has no inference credential and "
                    "cannot be scored. Seal your provider key and commit the "
                    "sealed_inference_key file.",
                    path=SEALED_KEY_FILENAME,
                )
            )
        else:
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

    # Screening inspects the first agent_main, but the sandbox runner executes
    # the last binding Python keeps, so a decoy-first + shadow-last pair could
    # otherwise slip a no-op or answer-bank body past every single-definition
    # check below. Require exactly one top-level agent_main definition.
    if count_module_function_defs(tree, "agent_main") > 1:
        findings.append(
            reject_finding(
                "sn60.agent_main_duplicate",
                "Submission defines agent_main more than once; define it exactly "
                "once. The SN60 runner executes the last definition, which "
                "screening cannot validate.",
                path=AGENT_ENTRY_FILENAME,
            )
        )
        return dedupe_findings(findings)

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
                    f"SN60 screening rejected benchmark-answer leakage token: `{token}`.",
                    path=AGENT_ENTRY_FILENAME,
                )
            )
    return dedupe_findings(findings)


def validate_sn60_static_screening(candidate_root: str | Path) -> list[str]:
    from kata.submissions.bundle import load_bundle_files

    root = Path(candidate_root).expanduser().resolve()
    return finding_reasons(screen_sn60_static_bundle(load_bundle_files(root)))
