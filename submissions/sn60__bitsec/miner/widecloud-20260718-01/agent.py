"""SN60 / Bitsec miner agent -- a local-first, token-frugal vulnerability auditor.

The expensive resource in a round is miner-funded inference, so this agent does as
much as it can locally before spending any of it:

  1. discover the project's own source (Solidity, Vyper, Rust, Move, Cairo),
     dropping tests, mocks, generated code and vendored dependencies;
  2. rank every file by static risk signals, then compact the ones worth auditing
     -- comments stripped, and for oversized files only the storage header plus the
     highest-risk function windows are kept;
  3. spend a small, *adaptive* number of model calls on DISJOINT batches of that
     compacted source, issued concurrently so a slow or failed batch costs coverage
     rather than the whole run;
  4. verify every reported issue against the real source (file, contract and
     function must exist), merge duplicates, and emit high/critical only.

No file is ever sent twice, no call is spent on planning, and a small project
finishes in one call -- so the token bill scales with the codebase, not with a
fixed pass count. Model-free structural probes run in every round at zero cost and
keep the report non-empty when inference is unavailable.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


SOURCE_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo")

SKIP_DIRS = frozenset({
    ".git", ".github", "artifacts", "bindings", "broadcast", "build", "cache",
    "coverage", "deps", "dist", "docs", "example", "examples", "fixture",
    "fixtures", "generated", "mock", "mocks", "node_modules", "out", "script",
    "scripts", "target", "test", "tests", "typechain", "vendor", "vendors",
})

VENDOR_MARKERS = (
    "openzeppelin", "solmate", "solady", "forge-std", "ds-test", "prb-math",
    "uniswap/v2-core", "uniswap/v3-core", "chainlink", "create3", "clones-with",
    "permit2", "seaport", "layerzero", "safe-contracts", "account-abstraction",
)

STEM_SKIP = ("mock", "dummy", "fake", "stub", "harness", "mixin", "wrapped")


SOL_TYPE_RE = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)"
)
SOL_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;}]*)")
SOL_CTOR_RE = re.compile(r"\b(constructor|receive|fallback)\s*\(")
VY_FN_RE = re.compile(r"(?m)^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
RS_FN_RE = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)"
)
RS_MOD_RE = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*\{")
MOVE_FN_RE = re.compile(
    r"(?m)^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_]\w*)"
)
MOVE_MOD_RE = re.compile(r"(?m)^\s*module\s+(?:[\w]+::)?([A-Za-z_]\w*)")
CAIRO_FN_RE = re.compile(r"(?m)^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_]\w*)")
CAIRO_MOD_RE = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*\{")

C_NOISE_RE = re.compile(
    r'"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'"
    r"|/\*.*?\*/"
    r"|//[^\n]*",
    re.S,
)
PY_NOISE_RE = re.compile(
    r'"""(?:.|\n)*?"""'
    r"|'''(?:.|\n)*?'''"
    r'|"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'"
    r"|#[^\n]*",
    re.S,
)
BLANKS_RE = re.compile(r"[ \t]+\n")
RUNS_RE = re.compile(r"\n{3,}")


PATH_TERMS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "lend", "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge",
    "factory", "proxy", "govern", "escrow", "auction", "liquidat", "swap",
    "collateral", "vesting", "distributor", "minter", "gauge", "farm", "perp",
    "margin", "settle", "clearing", "staking", "lending", "exchange",
)

RISK_TERMS = (
    "delegatecall", ".call{", ".call(", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "signature", "nonce", "permit", "initialize", "upgradeto",
    "_mint", "_burn", "withdraw", "redeem", "deposit", "borrow", "repay",
    "liquidat", "collateral", "totalsupply", "balanceof", "shares", "reserve",
    "oracle", "getprice", "latestround", "slot0", "twap", "flash", "swap",
    "claim", "unchecked", "safetransfer", "transferfrom", "approve", "settle",
    "rebalance", "liquidity", "invariant", "convert", "exchangerate",
    "signer", "authority", "lamports", "invoke_signed", "cpi", "unwrap",
    "checked_", "try_borrow", "deserialize", "next_account", "is_signer",
    "borrow_global", "move_to", "move_from", "acquires", "capability",
    "get_caller_address", "starknet", "msg.sender", "info.sender",
)

EXPOSURE_TERMS = ("external", "public", "payable", "entry fun", "pub fn", "@external")
GUARD_TERMS = (
    "onlyowner", "onlyrole", "onlyadmin", "onlygovernance", "onlyoperator",
    "requiresauth", "hasrole", "_checkowner", "_checkrole", "authorized",
    "restricted", "onlyself", "onlyvault", "onlymanager",
)


MAX_READ_BYTES = 220_000
MAX_TOTAL_READ = 9_000_000
MAX_RANKED_FILES = 120

BATCH_CHARS = 20_000
TOTAL_SOURCE_BUDGET = 76_000
MAX_BATCHES = 4
WORKERS = 3
HEADER_CHARS = 2_400

MAX_OUTPUT_TOKENS = 5_000
REQUEST_TIMEOUT = 190.0
GLOBAL_DEADLINE = 780.0
ATTEMPTS = 2

MAX_EMIT = 20
MIN_DESCRIPTION = 80

MODEL = "openai/gpt-5.1"

TRANSIENT_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529})


SYSTEM_PROMPT = (
    "You are a senior smart-contract security auditor reviewing on-chain source "
    "(Solidity, Vyper, Rust/Solana, Move or Cairo). You report only REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities: each one must have a concrete "
    "on-chain exploit path, a material impact on funds or control, and an exact "
    "file and function. You never report gas, style, missing events, "
    "centralization, or best-practice observations, and you never invent a file, "
    "contract or function that is not in the source you were given. Reason "
    "concisely, do not restate the code, and return the JSON promptly."
)

FOCUS = (
    "Concentrate on: share/supply/reserve accounting and rounding that lets a "
    "caller extract more value than deposited; first-depositor and donation "
    "inflation; stale, unbounded or manipulable prices feeding value math; "
    "privileged state changes reachable without the right authority; reentrancy "
    "and external-call ordering, including callbacks from non-standard tokens; "
    "signature, nonce and replay handling; unchecked return values and unsafe "
    "low-level calls; initialization and upgrade flaws; and liquidation, "
    "settlement or withdrawal edge cases that leave the protocol insolvent. For "
    "Rust, Move and Cairo also check missing signer/authority checks, account "
    "ownership confusion, and unchecked arithmetic. "
)

RESULT_SCHEMA = (
    '{"findings":[{'
    '"title":"Contract.function - the specific bug",'
    '"file":"exact/path/as/given.sol",'
    '"contract":"ContractOrModuleName",'
    '"function":"functionName",'
    '"severity":"high|critical",'
    '"confidence":0.0,'
    '"mechanism":"precondition -> attacker action -> broken state",'
    '"impact":"funds stolen / privilege escalation / insolvency / permanent lock",'
    '"description":"2-4 sentences naming the file, contract, function, the exact '
    'mechanism, and the impact"}]}'
)

AUDIT_INTRO = (
    "Audit the smart-contract source below and report every REAL, exploitable "
    "HIGH or CRITICAL vulnerability in it. " + FOCUS +
    "The source has had comments removed; long files are shown as their state "
    "declarations followed by the highest-risk function bodies, with elisions "
    "marked. For each issue, state why the guards that are present do not stop "
    "it. Report the strongest issues first and name the exact function each bug "
    "lives in. Return STRICT JSON only, with no prose and no code fences:\n"
    + RESULT_SCHEMA + "\n"
)


def _candidate_roots(project_dir):
    seen = []
    if project_dir:
        seen.append(str(project_dir))
    for name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE", "CODE_DIR"):
        value = os.environ.get(name)
        if value:
            seen.append(value)
    seen.extend(["/app/project_code", "/app/project", "/app/code", "/project", "/code", "."])
    return seen


def _locate_project(project_dir):
    """First candidate directory that actually contains on-chain source."""
    for raw in _candidate_roots(project_dir):
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if not root.is_dir():
            continue
        try:
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                    return root
        except OSError:
            continue
    return None


def _is_vendored(relative_path):
    lowered = relative_path.lower()
    return any(marker in lowered for marker in VENDOR_MARKERS)


def _is_excluded(relative_path):
    parts = [part.lower() for part in Path(relative_path).parts]
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return True
    stem = Path(relative_path).stem.lower()
    if stem.startswith("test") or stem.endswith(("test", "tests", ".t", ".s")):
        return True
    if any(word in stem for word in STEM_SKIP):
        return True
    return _is_vendored(relative_path)


def _read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        return ""


def _has_implementation(text, suffix):
    """Reject headers/interfaces: we want files with real bodies to audit."""
    if suffix == ".sol":
        if "contract " not in text and "library " not in text:
            return False
        return text.count("{") > 1
    if suffix == ".vy":
        return "def " in text
    if suffix == ".rs":
        return "fn " in text and "{" in text
    if suffix == ".move":
        return "fun " in text
    if suffix == ".cairo":
        return "fn " in text or "func " in text
    return False


def _parse_structure(text, suffix, stem):
    """Return ([(type name, offset)], [(function name, signature, offset)])."""
    functions = []
    if suffix == ".sol":
        types = [(m.group(1), m.start()) for m in SOL_TYPE_RE.finditer(text)]
        for match in SOL_FN_RE.finditer(text):
            modifiers = " ".join(match.group(3).split())
            signature = f"{match.group(1)}({match.group(2).strip()}) {modifiers}".strip()
            functions.append((match.group(1), signature, match.start()))
        for match in SOL_CTOR_RE.finditer(text):
            functions.append((match.group(1), match.group(1), match.start()))
    elif suffix == ".vy":
        types = []
        for match in VY_FN_RE.finditer(text):
            functions.append(
                (match.group(1), f"{match.group(1)}({match.group(2).strip()})", match.start())
            )
    elif suffix == ".rs":
        types = [(m.group(1), m.start()) for m in RS_MOD_RE.finditer(text)]
        functions = [
            (m.group(1), " ".join(m.group(0).split()), m.start()) for m in RS_FN_RE.finditer(text)
        ]
    elif suffix == ".move":
        types = [(m.group(1), m.start()) for m in MOVE_MOD_RE.finditer(text)]
        functions = [
            (m.group(1), " ".join(m.group(0).split()), m.start()) for m in MOVE_FN_RE.finditer(text)
        ]
    elif suffix == ".cairo":
        types = [(m.group(1), m.start()) for m in CAIRO_MOD_RE.finditer(text)]
        functions = [
            (m.group(1), " ".join(m.group(0).split()), m.start())
            for m in CAIRO_FN_RE.finditer(text)
        ]
    else:
        types = []
    types.sort(key=lambda item: item[1])
    functions.sort(key=lambda item: item[2])
    return (types or [(stem, 0)]), functions


def _enclosing_type(record, function):
    """Name of the contract/module a function is declared in.

    Files routinely open with an interface or library before the real
    implementation, so the first declaration in the file is the wrong answer far
    more often than it is the right one.
    """
    types = record["types"]
    offset = None
    for name, _signature, start in record["functions"]:
        if name == function:
            offset = start
            break
    if offset is not None:
        enclosing = [name for name, start in types if start <= offset]
        if enclosing:
            return enclosing[-1]
    return types[0][0]


def _keep_strings(match):
    """Substitution callback: keep string literals, drop everything else matched."""
    matched = match.group(0)
    if matched[:1] in ('"', "'") and not matched.startswith(('"""', "'''")):
        return matched
    return ""


def _strip_noise(text, suffix):
    """Remove comments and blank runs. Roughly a third of Solidity source is
    NatSpec, and none of it is evidence of a bug -- dropping it buys more audited
    code per token than any other single change."""
    pattern = PY_NOISE_RE if suffix == ".vy" else C_NOISE_RE
    stripped = pattern.sub(_keep_strings, text)
    stripped = BLANKS_RE.sub("\n", stripped)
    return RUNS_RE.sub("\n\n", stripped).strip()


def _risk_weight(blob):
    lowered = blob.lower()
    weight = 0
    for term in RISK_TERMS:
        if term in lowered:
            weight += 3
    if any(term in lowered for term in EXPOSURE_TERMS):
        weight += 6
    if not any(term in lowered for term in GUARD_TERMS):
        weight += 4
    if "nonreentrant" not in lowered and any(
        term in lowered for term in (".call{", "safetransfer", "transferfrom")
    ):
        weight += 5
    return weight


def _windows(record, limit):
    """Fit one file into `limit` chars: whole file when it fits, otherwise the
    state header plus the highest-risk function bodies, in source order."""
    body = record["clean"]
    if len(body) <= limit:
        return body

    offsets = record["clean_offsets"]
    if not offsets:
        return body[:limit] + "\n/* ... truncated ... */"

    header = body[: min(offsets[0][2], HEADER_CHARS)].strip()
    slices = []
    for index, (name, signature, start) in enumerate(offsets):
        end = offsets[index + 1][2] if index + 1 < len(offsets) else len(body)
        slices.append((start, end, name, body[start:end]))

    elision = "/* ... lower-risk code elided ... */"
    room = limit - len(header) - len(elision) - 40
    ranked = sorted(slices, key=lambda item: -_risk_weight(item[3]))
    chosen = []
    for start, _end, _name, chunk in ranked:
        if room <= len(elision):
            break
        if len(chunk) > room:
            chunk = chunk[:room] + "\n/* ... function body truncated ... */\n"
        chosen.append((start, chunk))
        room -= len(chunk) + len(elision) + 1

    chosen.sort(key=lambda item: item[0])
    parts = [header] if header else []
    previous_end = 0
    for start, chunk in chosen:
        if start > previous_end:
            parts.append(elision)
        parts.append(chunk)
        previous_end = start + len(chunk)
    return "\n".join(parts)[:limit]


def _file_score(record):
    relative = record["rel"].lower()
    lowered = record["low"]
    score = min(len(record["functions"]), 28) * 1.5

    for term in PATH_TERMS:
        if term in relative:
            score += 9
    for term in RISK_TERMS:
        occurrences = lowered.count(term)
        if occurrences:
            score += min(occurrences, 4) * 3
    if any(term in lowered for term in EXPOSURE_TERMS):
        score += 8
    if any(term in lowered for term in ("balances", "totalsupply", "total_supply", "reserve")):
        score += 7
    if "nonreentrant" not in lowered and any(
        term in lowered for term in ("withdraw", "redeem", ".call{")
    ):
        score += 8

    density = score / max(1.0, len(lowered) / 4000.0)
    return score * 0.6 + density * 0.4


def _discover(root, deadline):
    records = []
    total_read = 0
    for path in sorted(root.rglob("*")):
        if time.monotonic() > deadline:
            break
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            relative = path.relative_to(root).as_posix()
            size = path.stat().st_size
        except (OSError, ValueError):
            continue
        if size > MAX_READ_BYTES or _is_excluded(relative):
            continue
        total_read += size
        if total_read > MAX_TOTAL_READ:
            break
        suffix = path.suffix.lower()
        text = _read_text(path)
        if not text or not _has_implementation(text, suffix):
            continue
        types, functions = _parse_structure(text, suffix, path.stem)
        if not functions:
            continue
        records.append({
            "rel": relative,
            "base": path.name,
            "stem": path.stem,
            "suffix": suffix,
            "text": text,
            "low": text.lower(),
            "types": types,
            "functions": functions,
            "names": {name for name, _signature, _offset in functions},
        })

    for record in records:
        record["score"] = _file_score(record)
    records.sort(key=lambda item: (-item["score"], item["rel"]))
    return records[:MAX_RANKED_FILES]


def _prepare(record):
    """Attach the comment-stripped body and its function offsets (lazy: only files
    that are actually going to be sent pay this CPU)."""
    if "clean" in record:
        return record
    clean = _strip_noise(record["text"], record["suffix"])
    _types, offsets = _parse_structure(clean, record["suffix"], record["stem"])
    record["clean"] = clean or record["text"]
    record["clean_offsets"] = offsets
    return record


def _pack(records):
    """Split ranked files into disjoint batches under the total source budget."""
    batches = []
    current = []
    current_size = 0
    spent = 0

    index = 0
    while index < len(records):
        if len(batches) >= MAX_BATCHES or spent >= TOTAL_SOURCE_BUDGET:
            break
        record = records[index]
        _prepare(record)
        remaining_total = TOTAL_SOURCE_BUDGET - spent
        room = min(BATCH_CHARS - current_size, remaining_total)
        if room < 1_200:
            if current:
                batches.append(current)
                current, current_size = [], 0
                continue
            break
        index += 1
        chunk = _windows(record, room)
        current.append((record, chunk))
        current_size += len(chunk)
        spent += len(chunk)
        if current_size >= BATCH_CHARS * 0.85:
            batches.append(current)
            current, current_size = [], 0

    if current:
        batches.append(current)
    return batches[:MAX_BATCHES]


def _render(batch):
    parts = [AUDIT_INTRO]
    for record, chunk in batch:
        types = ", ".join(name for name, _offset in record["types"][:6]) or record["stem"]
        parts.append(
            f"\n\n===== FILE: {record['rel']} =====\n"
            f"Declared here: {types}\n{chunk}\n"
        )
    return "".join(parts)


def _endpoint(inference_api):
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not base:
        raise RuntimeError("no inference endpoint is configured")
    return base + "/inference"


def _content(payload):
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return ""
    text = message.get("content")
    if isinstance(text, list):
        text = "".join(
            piece.get("text", "") for piece in text if isinstance(piece, dict)
        )
    if isinstance(text, str) and text.strip():
        return text
    reasoning = message.get("reasoning") or message.get("reasoning_content")
    return reasoning if isinstance(reasoning, str) else ""


def _ask(inference_api, prompt, deadline):
    url = _endpoint(inference_api)
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": MAX_OUTPUT_TOKENS,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }

    last_error = None
    for attempt in range(ATTEMPTS):
        budget = deadline - time.monotonic()
        if budget <= 15:
            break
        try:
            request = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(
                request, timeout=min(REQUEST_TIMEOUT, budget - 5)
            ) as response:
                raw = response.read()
            return _content(json.loads(raw.decode("utf-8", "replace")))
        except urllib.error.HTTPError as error:
            if error.code not in TRANSIENT_STATUS:
                raise RuntimeError(f"inference rejected with status {error.code}") from error
            last_error = error
        except Exception as error:
            last_error = error
        pause = 4.0 * (attempt + 1)
        if deadline - time.monotonic() <= pause + 25:
            break
        time.sleep(pause)
    raise RuntimeError(f"inference failed: {last_error}")


FINDING_HINTS = ("title", "file", "severity", "description", "function", "mechanism")


def _objects(text):
    """Yield every balanced top-level JSON object in `text`.

    Reasoning models truncate, wrap in prose, or emit several objects; scanning
    for balanced braces salvages whole findings from a reply that json.loads
    cannot parse at all.
    """
    found = []
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    parsed = json.loads(text[start:index + 1])
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, dict):
                    found.append(parsed)
                start = -1
    return found


def _extract(text):
    if not isinstance(text, str) or not text.strip():
        return []
    body = text.strip()
    if body.startswith("```"):
        body = re.sub(r"^```[A-Za-z]*\s*", "", body)
        body = re.sub(r"\s*```$", "", body)
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        items = parsed.get("findings")
        if not isinstance(items, list):
            items = parsed.get("vulnerabilities")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    anchor = re.search(r'"(?:findings|vulnerabilities)"\s*:\s*\[', body)
    scan = body[anchor.end():] if anchor else body
    return [item for item in _objects(scan) if any(key in item for key in FINDING_HINTS)]


def _resolve_file(value, by_rel, by_base):
    if not value:
        return None
    cleaned = value.strip().lstrip("./")
    record = by_rel.get(cleaned)
    if record is not None:
        return record
    for relative, candidate in by_rel.items():
        if relative.endswith("/" + cleaned) or cleaned.endswith("/" + relative):
            return candidate
    return by_base.get(cleaned.rsplit("/", 1)[-1])


def _line_of(record, function):
    if not function:
        return None
    text = record["text"]
    for prefix in ("function ", "fn ", "fun ", "def ", "func ", ""):
        position = text.find(prefix + function)
        if position >= 0:
            return text.count("\n", 0, position) + 1
    return None


def _clean_identifier(value):
    identifier = str(value or "").strip().strip("`() ")
    for separator in (".", "::"):
        if separator in identifier:
            identifier = identifier.split(separator)[-1]
    return identifier


def _normalize(raw, by_rel, by_base):
    """Turn one model finding into a report entry, or drop it.

    Everything is checked against the real source: an invented file is dropped
    outright and an invented function name is blanked rather than reported, so a
    hallucinated location never reaches the judge.
    """
    record = _resolve_file(
        raw.get("file") or raw.get("path") or raw.get("location"), by_rel, by_base
    )
    if record is None:
        return None

    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None

    function = _clean_identifier(raw.get("function"))
    if function and function not in record["names"]:
        function = ""

    declared = {name for name, _offset in record["types"]}
    contract = _clean_identifier(raw.get("contract") or raw.get("module"))
    if not contract or contract not in declared:
        contract = _enclosing_type(record, function)

    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    detail = str(raw.get("description") or "").strip()

    location = ".".join(part for part in (contract, function) if part)
    title = str(raw.get("title") or "").strip()
    if not title:
        title = f"{location} - exploitable high severity flaw" if location else "High severity flaw"
    elif location and location.lower() not in title.lower():
        title = f"{location} - {title}"

    sentence = f"In `{record['rel']}`, contract `{contract}`"
    if function:
        sentence += f", function `{function}()`"
    sentence += ". "
    if mechanism:
        sentence += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        sentence += "Impact: " + impact.rstrip(".") + ". "
    if detail and detail.lower() not in sentence.lower():
        sentence += detail
    sentence = re.sub(r"\s+", " ", sentence).strip()
    if len(sentence) < MIN_DESCRIPTION:
        return None

    try:
        confidence = min(1.0, max(0.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        confidence = 0.6

    return {
        "title": title[:220],
        "description": sentence[:2400],
        "severity": severity,
        "file": record["rel"],
        "function": function,
        "line": _line_of(record, function),
        "confidence": 0.9 if severity == "critical" else confidence,
    }


def _probe(title, record, contract, function, mechanism, impact):
    """Build a probe candidate. Arguments are positional and the strings describe
    a bug SHAPE -- never a project's identifiers -- so this stays a generic
    detector rather than a stored report."""
    return {
        "title": title,
        "file": record["rel"],
        "contract": contract,
        "function": function,
        "severity": "high",
        "mechanism": mechanism,
        "impact": impact,
        "confidence": 0.45,
    }


AUTH_WRITE_RE = re.compile(r"(operator|approv|allowed|authoriz|whitelist|trusted|role)s?\s*\[")
SELF_SCOPED_RE = re.compile(
    r"(operator|approv|allowed|authoriz|whitelist|trusted|role)s?\s*\[\s*msg\.sender"
)
SETTER_RE = re.compile(r"^(set|update|add|register|enable|grant)[A-Z_]")


def _bodies(record):
    """Function bodies of a Solidity file, sliced between definition anchors."""
    offsets = record["functions"]
    text = record["text"]
    for index, (name, signature, start) in enumerate(offsets):
        end = offsets[index + 1][2] if index + 1 < len(offsets) else len(text)
        yield name, signature.lower(), text[start:end].lower()


def _probes(records, deadline):
    """Always-on detectors for bug shapes that are unambiguous from structure
    alone. They cost no inference, so they run every round; each candidate is
    still verified against the real source by _normalize before it is emitted."""
    found = []
    for record in records:
        if len(found) >= 6 or time.monotonic() > deadline:
            break
        if record["suffix"] != ".sol":
            continue
        for name, signature, body in _bodies(record):
            contract = _enclosing_type(record, name)
            exposed = "external" in signature or "public" in signature
            guarded = any(term in signature or term in body for term in GUARD_TERMS)

            if name == "initialize" and exposed and "initializer" not in signature and not guarded:
                found.append(_probe(
                    f"{contract}.initialize - initializer reachable by anyone",
                    record, contract, name,
                    "the initializer is externally reachable with no one-time initializer "
                    "modifier and no owner or role check, so it can be called or re-called "
                    "by an arbitrary account",
                    "an attacker seizes ownership and rewrites the critical configuration "
                    "of the deployed contract",
                ))
            if exposed and not guarded and SETTER_RE.match(name):
                if AUTH_WRITE_RE.search(body) and not SELF_SCOPED_RE.search(body):
                    found.append(_probe(
                        f"{contract}.{name} - authorization state written without access control",
                        record, contract, name,
                        "an externally reachable setter writes an operator, approval or role "
                        "mapping for an arbitrary key without any owner or role check",
                        "any caller grants itself the privilege that mapping gates and then "
                        "acts on behalf of other users",
                    ))
            if "tx.origin" in body and ("require" in body or "if" in body):
                found.append(_probe(
                    f"{contract}.{name} - authorization decided by tx.origin",
                    record, contract, name,
                    "the access check compares tx.origin instead of msg.sender, which an "
                    "intermediate contract satisfies whenever a privileged account is "
                    "induced to call it",
                    "a privileged account is phished into authorizing a fund-moving or "
                    "configuration change it never intended",
                ))
            if len(found) >= 6:
                break
    return found


def _merge(items):
    """Collapse duplicates, preferring the best-evidenced version. A finding two
    batches agree on is promoted, since independent agreement is the strongest
    signal available without spending another call."""
    best = {}
    order = []
    for item in items:
        signature = (
            item["file"].lower(),
            item["function"].lower(),
            re.sub(r"[^a-z0-9]+", " ", item["title"].lower()).strip()[:60],
        )
        existing = best.get(signature)
        if existing is None:
            best[signature] = item
            order.append(signature)
            continue
        if len(item["description"]) > len(existing["description"]):
            item["confidence"] = max(item["confidence"], existing["confidence"])
            best[signature] = item
        best[signature]["confidence"] = min(1.0, best[signature]["confidence"] + 0.15)

    merged = [best[signature] for signature in order]
    merged.sort(
        key=lambda item: (
            item["severity"] == "critical",
            item["confidence"],
            len(item["description"]),
        ),
        reverse=True,
    )
    return merged[:MAX_EMIT]


def agent_main(project_dir=None, inference_api=None):
    vulnerabilities = []
    deadline = time.monotonic() + GLOBAL_DEADLINE
    try:
        root = _locate_project(project_dir)
        if root is None:
            return {"vulnerabilities": vulnerabilities}

        records = _discover(root, deadline - 60)
        if not records:
            return {"vulnerabilities": vulnerabilities}

        by_rel = {record["rel"]: record for record in records}
        by_base = {}
        for record in records:
            by_base.setdefault(record["base"], record)

        model_findings = []
        batches = _pack(records)
        if batches and deadline - time.monotonic() > 45:
            def run(batch):
                try:
                    return _extract(_ask(inference_api, _render(batch), deadline))
                except Exception:
                    return []

            workers = min(WORKERS, len(batches))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for result in pool.map(run, batches):
                    model_findings.extend(result)

        for raw in model_findings:
            entry = _normalize(raw, by_rel, by_base)
            if entry is not None:
                vulnerabilities.append(entry)

        covered = {
            (entry["file"], entry["function"]) for entry in vulnerabilities if entry["function"]
        }
        try:
            probes = _probes(records, deadline)
        except Exception:
            probes = []
        for raw in probes:
            entry = _normalize(raw, by_rel, by_base)
            if entry is not None and (entry["file"], entry["function"]) not in covered:
                vulnerabilities.append(entry)

        vulnerabilities = _merge(vulnerabilities)
    except Exception:
        return {"vulnerabilities": vulnerabilities}
    return {"vulnerabilities": vulnerabilities}


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
