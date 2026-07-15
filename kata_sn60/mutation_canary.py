"""Layer 2 anti-gaming: the renaming-invariance canary.

A benchmark *memorizer* keys its findings on identifiers that are unique to specific
benchmark projects (e.g. ``redelegateWithdrawnHYPE``) and returns canned answers. Its
findings therefore *collapse* when those identifiers are renamed. A genuine analyzer
reasons about logic, not names, so its findings *survive* renaming.

This module renames the distinctive identifiers in a project's source and compares an
agent's findings on the original vs. the renamed source. Findings that appear verbatim
on the original but vanish under renaming are rename-dependent -- the signature of a
fingerprint. The result is a REVIEW signal (never an auto-reject): a human confirms.

The core (rename + compare) is pure and fully testable. Production wires
``run_rename_invariance_canary`` with a real sandbox agent runner and a source provider
that reads the project's source; those I/O seams are injected so this stays unit-tested.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

# Identifiers we must never rename: renaming them would change meaning for a real
# analyzer too (false positives). Solidity keywords, value types, globals, and the most
# common standard/ERC identifiers. User/project identifiers are everything else.
SOLIDITY_RESERVED: frozenset[str] = frozenset(
    {
        # keywords / declarations / control flow
        "pragma",
        "solidity",
        "import",
        "from",
        "as",
        "contract",
        "interface",
        "library",
        "abstract",
        "is",
        "function",
        "modifier",
        "constructor",
        "fallback",
        "receive",
        "event",
        "error",
        "struct",
        "enum",
        "mapping",
        "using",
        "returns",
        "return",
        "if",
        "else",
        "for",
        "while",
        "do",
        "break",
        "continue",
        "try",
        "catch",
        "throw",
        "emit",
        "new",
        "delete",
        "revert",
        "require",
        "assert",
        "assembly",
        "unchecked",
        "type",
        "immutable",
        "constant",
        "override",
        "virtual",
        # visibility / mutability / location
        "public",
        "private",
        "internal",
        "external",
        "view",
        "pure",
        "payable",
        "nonpayable",
        "memory",
        "storage",
        "calldata",
        "indexed",
        "anonymous",
        # value types
        "address",
        "bool",
        "string",
        "bytes",
        "byte",
        "int",
        "uint",
        "fixed",
        "ufixed",
        "wei",
        "gwei",
        "ether",
        "seconds",
        "minutes",
        "hours",
        "days",
        "weeks",
        "true",
        "false",
        "mapping",
        # globals / builtins
        "msg",
        "block",
        "tx",
        "this",
        "super",
        "abi",
        "now",
        "gasleft",
        "blockhash",
        "keccak256",
        "sha256",
        "ripemd160",
        "ecrecover",
        "addmod",
        "mulmod",
        "selfdestruct",
        "sender",
        "value",
        "data",
        "sig",
        "gas",
        "timestamp",
        "number",
        "origin",
        "chainid",
        "coinbase",
        "difficulty",
        # extremely common std/ERC members (renaming these hurts real analyzers)
        "transfer",
        "transferfrom",
        "approve",
        "allowance",
        "balanceof",
        "totalsupply",
        "mint",
        "burn",
        "owner",
        "length",
        "push",
        "pop",
        "call",
        "delegatecall",
        "staticcall",
        "send",
        "encode",
        "decode",
        "encodepacked",
    }
)

# uint8..uint256 / int8..int256 / bytes1..bytes32 are reserved too.
_SIZED_TYPE = re.compile(r"^(u?int|bytes)([0-9]+)$")

# Only rename identifiers distinctive enough to be fingerprints: camelCase, snake_case,
# or long. Short all-lowercase words (e.g. "amount", "queue") are left alone to avoid
# disturbing a real analyzer.
_DISTINCTIVE_MIN_LEN = 6

# Solidity identifiers.
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
# Strings and comments, matched first so we never rename inside them.
_STRING_OR_COMMENT = re.compile(
    r"""
    //[^\n]*                |   # line comment
    /\*.*?\*/               |   # block comment
    "(?:\\.|[^"\\])*"       |   # double-quoted string
    '(?:\\.|[^'\\])*'           # single-quoted string
    """,
    re.VERBOSE | re.DOTALL,
)


def _is_reserved(identifier: str) -> bool:
    lowered = identifier.lower()
    return lowered in SOLIDITY_RESERVED or bool(_SIZED_TYPE.match(lowered))


def _is_distinctive(identifier: str) -> bool:
    core = identifier.lstrip("_$")
    if len(identifier) < _DISTINCTIVE_MIN_LEN:
        return False
    has_camel = any(ch.isupper() for ch in core[1:])
    has_underscore = "_" in identifier.strip("_")
    return has_camel or has_underscore or len(core) >= 10


def _renamed_token(identifier: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{identifier}".encode()).hexdigest()[:10]
    return f"z{digest}"


def rename_solidity_identifiers(source: str, *, salt: str = "canary") -> tuple[str, dict[str, str]]:
    """Consistently rename distinctive project identifiers, preserving code structure.

    Strings and comments are untouched. Reserved/standard identifiers are preserved so a
    genuine analyzer still sees the same logic. Returns the renamed source and the
    ``original -> renamed`` map.
    """
    mapping: dict[str, str] = {}

    # Mask strings/comments so identifiers inside them are never renamed.
    masked_spans: list[str] = []

    def _mask(match: re.Match[str]) -> str:
        masked_spans.append(match.group(0))
        return f"\x00{len(masked_spans) - 1}\x00"

    masked = _STRING_OR_COMMENT.sub(_mask, source)

    def _rename(match: re.Match[str]) -> str:
        identifier = match.group(0)
        if _is_reserved(identifier) or not _is_distinctive(identifier):
            return identifier
        if identifier not in mapping:
            mapping[identifier] = _renamed_token(identifier, salt)
        return mapping[identifier]

    renamed_masked = _IDENT.sub(_rename, masked)

    # Restore the masked strings/comments.
    def _unmask(match: re.Match[str]) -> str:
        return masked_spans[int(match.group(1))]

    renamed = re.sub(r"\x00(\d+)\x00", _unmask, renamed_masked)
    return renamed, mapping


def _finding_key(finding: dict) -> str:
    """A verbatim identity for a finding: canned findings are byte-identical prose."""
    title = str(finding.get("title") or "").strip().lower()
    description = str(finding.get("description") or "").strip().lower()
    return f"{title}\x00{description}"


def stable_findings(run_results: list[list[dict]]) -> list[dict]:
    """Findings that appear byte-identically in EVERY run.

    Real agents are hybrids: a deterministic pattern layer plus a non-deterministic LLM
    audit whose findings are reworded run-to-run. Only findings identical across all
    runs are deterministic -- the hallmark of a hardcoded/canned finding. Isolating
    these makes the canary robust to inference non-determinism (no false positives from
    LLM rewording).
    """
    if not run_results:
        return []
    key_sets = [{_finding_key(f) for f in result} for result in run_results]
    stable_keys = set.intersection(*key_sets)
    seen: set[str] = set()
    out: list[dict] = []
    for finding in run_results[0]:
        key = _finding_key(finding)
        if key in stable_keys and key not in seen:
            seen.add(key)
            out.append(finding)
    return out


@dataclass(frozen=True)
class CanaryResult:
    suspicious: bool
    original_count: int
    renamed_count: int
    rename_dependent: list[str] = field(default_factory=list)
    reason: str = ""


def find_rename_dependent_findings(
    original_findings: list[dict],
    renamed_findings: list[dict],
) -> list[str]:
    """Verbatim findings present on the original but absent under renaming.

    Canned fingerprint findings are byte-identical prose that vanish when their
    hardcoded identifiers stop matching; genuine findings recur (possibly reworded).
    """
    renamed_keys = {_finding_key(f) for f in renamed_findings}
    dependent: list[str] = []
    for finding in original_findings:
        key = _finding_key(finding)
        if key not in renamed_keys:
            title = str(finding.get("title") or "").strip()
            if title:
                dependent.append(title)
    return dependent


def assess_rename_invariance(
    original_findings: list[dict],
    renamed_findings: list[dict],
    *,
    min_rename_dependent: int = 1,
) -> CanaryResult:
    """Flag (for review) when verbatim findings collapse under identifier renaming."""
    dependent = find_rename_dependent_findings(original_findings, renamed_findings)
    suspicious = len(dependent) >= min_rename_dependent
    reason = (
        f"{len(dependent)} finding(s) present on the original source vanished under "
        "identifier renaming -- the signature of hardcoded benchmark fingerprints "
        "rather than genuine analysis."
        if suspicious
        else "Findings survived identifier renaming (no fingerprint collapse detected)."
    )
    return CanaryResult(
        suspicious=suspicious,
        original_count=len(original_findings),
        renamed_count=len(renamed_findings),
        rename_dependent=dependent,
        reason=reason,
    )


def run_rename_invariance_canary(
    *,
    run_agent: Callable[[str], list[dict]],
    project_source: str,
    salt: str = "canary",
    original_runs: int = 2,
    min_rename_dependent: int = 1,
) -> CanaryResult:
    """Run the agent on the original and a renamed copy of the source, then assess.

    ``run_agent(source) -> findings`` is injected: production supplies a runner that
    executes the agent in the sandbox against the given source (original vs. a renamed
    overlay); tests supply an in-process stub. The original is run ``original_runs``
    times to isolate deterministic (canned) findings from non-deterministic LLM output,
    so only findings that are both stable AND rename-fragile are flagged.
    """
    original_results = [run_agent(project_source) for _ in range(max(1, original_runs))]
    deterministic = stable_findings(original_results)
    renamed_source, _mapping = rename_solidity_identifiers(project_source, salt=salt)
    renamed_findings = run_agent(renamed_source)
    return assess_rename_invariance(
        deterministic,
        renamed_findings,
        min_rename_dependent=min_rename_dependent,
    )
