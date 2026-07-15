"""Miner-funded inference relay for sealed SN60 execution.

Untrusted miner agents run inside an internet-blocked Docker network, so the only
way they can reach an LLM is through the inference endpoint Kata hands them via
``KATA_SN60_INFERENCE_API``. The relay forwards the miner's request and credential
to the configured provider while keeping the agent on an internal network. The
validator never receives or pays with a platform inference key.

By default the relay preserves the miner's requested model, sampling settings,
token settings, and number of calls. ``KATA_RELAY_ENFORCE_PLATFORM_POLICY=1`` is
an explicit legacy mode for a validator-funded environment; only that mode pins a
model, removes sampling fields, and enables request budgets.

The module has no third-party dependencies and runs as a small sidecar container
on the agent network:

    docker run --rm --name kata_model_relay --network bitsec-net \\
        -e KATA_RELAY_UPSTREAM=http://bitsec_proxy:8000 \\
        kata-sn60-model-relay

Then start the validator with ``KATA_SN60_INFERENCE_API=http://kata_model_relay:8000``.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_UPSTREAM = "http://bitsec_proxy:8000"
DEFAULT_PINNED_MODEL = "qwen/qwen3.6-35b-a3b"
DEFAULT_DIRECT_PINNED_MODEL = "Qwen/Qwen3.6-35B-A3B"
DEFAULT_DIRECT_UPSTREAM = "https://api.akashml.com/v1/chat/completions"
DEFAULT_TIMEOUT_SECONDS = 900

# Legacy operator-funded pricing defaults (USD per 1M tokens); override via env.
DEFAULT_PRICE_INPUT_PER_M = 0.14
DEFAULT_PRICE_OUTPUT_PER_M = 1.00

# Legacy operator-funded output-token ceiling. It is only applied when
# ``KATA_RELAY_ENFORCE_PLATFORM_POLICY=1``.
DEFAULT_MAX_OUTPUT_TOKENS = 32000

# Legacy operator-funded per-agent limits. They are inactive in the default
# miner-funded mode, where the miner supplies and pays for its own credential.
DEFAULT_AGENT_INPUT_TOKEN_BUDGET = 150000
DEFAULT_AGENT_TOKEN_BUDGET = 24000
DEFAULT_AGENT_CALL_BUDGET = 3

POLICY_ENFORCEMENT_ENV = "KATA_RELAY_ENFORCE_PLATFORM_POLICY"

# The only endpoint agents may use to reach their inference provider.
INFERENCE_PATH = "/inference"
# Answered by the relay itself so operators can prove the process is up without
# depending on the upstream proxy.
HEALTH_PATH = "/healthz"
# Lets an operator probe the upstream provider before starting a round. It is
# admin-protected because it deliberately spends the supplied inference key.
UPSTREAM_CHECK_PATH = "/healthz/upstream"
# Output-token ceiling for the inexpensive upstream probe.
HEALTHCHECK_MAX_TOKENS = 2000
# Relay-local cost accounting: read the running total, or zero it before a PR.
COST_PATH = "/costs"
COST_RESET_PATH = "/costs/reset"
ADMIN_TOKEN_ENV = "KATA_RELAY_ADMIN_TOKEN"
ADMIN_TOKEN_HEADER = "x-kata-relay-admin-token"
FORBIDDEN_SAMPLING_FIELDS = {
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "top_a",
    "frequency_penalty",
    "presence_penalty",
    "repetition_penalty",
    "seed",
    "logit_bias",
    "logprobs",
    "top_logprobs",
}

# Hop-by-hop headers must never be forwarded (RFC 7230 section 6.1); Host and
# Content-Length are recomputed by the outbound request instead of copied.
_SKIP_REQUEST_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
_SKIP_RESPONSE_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

PROXY_KEY_PREFIXES = ("sk-or-", "cpk_")
DEFAULT_DIRECT_KEY_PREFIXES = ("akml-", "akml_")
DEFAULT_DIRECT_AUTH_HEADER = "Authorization"
DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE = "Bearer {api_key}"


def platform_policy_enforced() -> bool:
    """Whether the legacy validator-funded inference restrictions are enabled."""
    return _env_truthy(POLICY_ENFORCEMENT_ENV)


class RelayConfigurationError(Exception):
    """Operator-controlled relay configuration is incomplete or invalid."""


@dataclass(frozen=True)
class DirectProviderConfig:
    upstream: str
    # Only used when the explicit legacy platform-policy mode is enabled.
    # Miner-funded forwarding preserves the model in the agent request.
    model: str = ""
    auth_header: str = DEFAULT_DIRECT_AUTH_HEADER
    auth_value_template: str = DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE


def is_akash_api_key(api_key: str | None) -> bool:
    """Return true when the inference key belongs to AkashML."""
    return _api_key_matches_prefixes(api_key, DEFAULT_DIRECT_KEY_PREFIXES)


def is_proxy_api_key(api_key: str | None) -> bool:
    """Return true for providers already supported by the sandbox proxy."""
    return _api_key_matches_prefixes(api_key, PROXY_KEY_PREFIXES)


def _api_key_matches_prefixes(api_key: str | None, prefixes: tuple[str, ...] | list[str]) -> bool:
    if not api_key:
        return False
    value = api_key.strip()
    return any(prefix == "*" or value.startswith(prefix) for prefix in prefixes)


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _direct_env_config() -> DirectProviderConfig:
    upstream = os.environ.get("KATA_RELAY_DIRECT_UPSTREAM", "").strip()
    model = os.environ.get("KATA_RELAY_DIRECT_MODEL", "").strip()
    if not upstream:
        raise RelayConfigurationError("direct provider routing requires KATA_RELAY_DIRECT_UPSTREAM")
    return DirectProviderConfig(
        upstream=upstream,
        model=model,
        auth_header=os.environ.get("KATA_RELAY_DIRECT_AUTH_HEADER", "").strip()
        or DEFAULT_DIRECT_AUTH_HEADER,
        auth_value_template=os.environ.get("KATA_RELAY_DIRECT_AUTH_VALUE_TEMPLATE", "").strip()
        or DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE,
    )


def resolve_direct_provider(api_key: str | None) -> DirectProviderConfig | None:
    """Resolve a direct OpenAI-compatible provider for keys the proxy cannot route.

    OpenRouter and Chutes keep their existing sandbox-proxy route. AkashML is the
    built-in direct provider. Future providers can be enabled without code changes:

      KATA_RELAY_DIRECT_KEY_PREFIXES=abc-,xyz_
      KATA_RELAY_DIRECT_UPSTREAM=https://provider.example/v1/chat/completions

    Use "*" as a prefix only when every non-proxy inference key should use the
    configured direct provider. ``KATA_RELAY_DIRECT_MODEL`` is only needed for
    the explicit legacy operator-funded policy.
    """
    if not api_key or is_proxy_api_key(api_key):
        return None

    custom_prefixes = _split_csv(os.environ.get("KATA_RELAY_DIRECT_KEY_PREFIXES"))
    if custom_prefixes and _api_key_matches_prefixes(api_key, custom_prefixes):
        return _direct_env_config()
    if _env_truthy("KATA_RELAY_DIRECT_ALLOW_UNKNOWN"):
        return _direct_env_config()
    if is_akash_api_key(api_key):
        return DirectProviderConfig(
            upstream=os.environ.get("KATA_RELAY_AKASH_UPSTREAM", "").strip()
            or DEFAULT_DIRECT_UPSTREAM,
            model=os.environ.get("KATA_RELAY_AKASH_MODEL", "").strip()
            or DEFAULT_DIRECT_PINNED_MODEL,
        )
    return None


def resolve_upstream() -> str:
    """Base URL of the real inference proxy the relay forwards to."""
    value = os.environ.get("KATA_RELAY_UPSTREAM")
    if value and value.strip():
        return value.strip().rstrip("/")
    return DEFAULT_UPSTREAM


def resolve_pinned_model(api_key: str | None = None) -> str:
    """Resolve the model for explicit legacy operator-policy mode only."""
    value = os.environ.get("KATA_RELAY_PINNED_MODEL")
    if value and value.strip() and value.strip() != DEFAULT_PINNED_MODEL:
        return value.strip()
    try:
        direct_provider = resolve_direct_provider(api_key)
    except RelayConfigurationError:
        direct_provider = None
    if direct_provider is not None and direct_provider.model:
        return direct_provider.model
    if value and value.strip():
        return value.strip()
    return DEFAULT_PINNED_MODEL


def resolve_max_output_tokens() -> int:
    """Ceiling the relay forces ``max_tokens`` up to so the reasoning model has
    room to think *and* answer without the proxy rejecting a length-truncated
    response. 0 disables the override (leave the caller's max_tokens as-is)."""
    value = os.environ.get("KATA_RELAY_MAX_OUTPUT_TOKENS")
    if value is None or not value.strip():
        return DEFAULT_MAX_OUTPUT_TOKENS
    try:
        parsed = int(value.strip())
    except ValueError:
        return DEFAULT_MAX_OUTPUT_TOKENS
    return parsed if parsed >= 0 else DEFAULT_MAX_OUTPUT_TOKENS


def _resolve_budget(env_var: str, default: int) -> int:
    value = os.environ.get(env_var)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value.strip())
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def resolve_agent_token_budget() -> int:
    """Max output tokens one agent may generate per problem (0 = unlimited)."""
    return _resolve_budget("KATA_RELAY_AGENT_TOKEN_BUDGET", DEFAULT_AGENT_TOKEN_BUDGET)


def resolve_agent_input_token_budget() -> int:
    """Max input tokens one agent may spend per problem (0 = unlimited)."""
    return _resolve_budget(
        "KATA_RELAY_AGENT_INPUT_TOKEN_BUDGET",
        DEFAULT_AGENT_INPUT_TOKEN_BUDGET,
    )


def resolve_agent_call_budget() -> int:
    """Max inference calls one agent may make per problem (0 = unlimited)."""
    return _resolve_budget("KATA_RELAY_AGENT_CALL_BUDGET", DEFAULT_AGENT_CALL_BUDGET)


def resolve_timeout() -> float:
    """Upstream request timeout; kept high because agent inference can be slow."""
    value = os.environ.get("KATA_RELAY_TIMEOUT")
    if value and value.strip():
        try:
            parsed = float(value.strip())
        except ValueError:
            return float(DEFAULT_TIMEOUT_SECONDS)
        if parsed > 0:
            return parsed
    return float(DEFAULT_TIMEOUT_SECONDS)


def resolve_admin_token() -> str:
    """Shared secret for relay operator endpoints.

    The relay is reachable by untrusted agent containers, so endpoints that can
    spend upstream tokens or mutate accounting must require an operator token.
    When unset, those endpoints are disabled rather than left open.
    """
    return os.environ.get(ADMIN_TOKEN_ENV, "").strip()


def _resolve_price(env_var: str, default: float) -> float:
    value = os.environ.get(env_var)
    if value and value.strip():
        try:
            parsed = float(value.strip())
        except ValueError:
            return default
        if parsed >= 0:
            return parsed
    return default


def resolve_price_input() -> float:
    """USD per 1M input tokens for relay accounting."""
    return _resolve_price("KATA_RELAY_PRICE_INPUT_PER_M", DEFAULT_PRICE_INPUT_PER_M)


def resolve_price_output() -> float:
    """USD per 1M output tokens for relay accounting."""
    return _resolve_price("KATA_RELAY_PRICE_OUTPUT_PER_M", DEFAULT_PRICE_OUTPUT_PER_M)


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def extract_usage(body: bytes) -> tuple[int, int, int]:
    """Pull (input, output, cached) token counts from an inference response.

    Prefers the OpenAI-style ``usage`` block; falls back to the proxy's flattened
    ``input_tokens``/``output_tokens`` fields. Returns zeros for anything we cannot
    read, so a surprising response body never breaks accounting or forwarding.
    """
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return (0, 0, 0)
    if not isinstance(payload, dict):
        return (0, 0, 0)

    input_tokens = output_tokens = cached_tokens = 0
    usage = payload.get("usage")
    if isinstance(usage, dict):
        input_tokens = _as_int(usage.get("prompt_tokens"))
        output_tokens = _as_int(usage.get("completion_tokens"))
        details = usage.get("prompt_tokens_details")
        if isinstance(details, dict):
            cached_tokens = _as_int(details.get("cached_tokens"))
    if input_tokens == 0:
        input_tokens = _as_int(payload.get("input_tokens"))
    if output_tokens == 0:
        output_tokens = _as_int(payload.get("output_tokens"))
    if cached_tokens == 0:
        cached_tokens = _as_int(payload.get("cached_tokens"))
    return (input_tokens, output_tokens, cached_tokens)


class CostMeter:
    """Thread-safe running total of agent inference tokens and their USD cost."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._input = 0
        self._output = 0
        self._cached = 0
        self._requests = 0

    def add(self, input_tokens: int, output_tokens: int, cached_tokens: int) -> None:
        with self._lock:
            self._input += input_tokens
            self._output += output_tokens
            self._cached += cached_tokens
            self._requests += 1

    def reset(self) -> None:
        with self._lock:
            self._input = 0
            self._output = 0
            self._cached = 0
            self._requests = 0

    def snapshot(self, price_input_per_m: float, price_output_per_m: float) -> dict:
        with self._lock:
            input_tokens = self._input
            output_tokens = self._output
            cached_tokens = self._cached
            requests = self._requests
        usd_input = round(input_tokens / 1_000_000 * price_input_per_m, 6)
        usd_output = round(output_tokens / 1_000_000 * price_output_per_m, 6)
        return {
            "requests": requests,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "price_input_per_1m_usd": price_input_per_m,
            "price_output_per_1m_usd": price_output_per_m,
            "usd_input": usd_input,
            "usd_output": usd_output,
            "usd_total": round(usd_input + usd_output, 6),
            "model": resolve_pinned_model() if platform_policy_enforced() else None,
        }


# Process-wide meter shared across handler threads. It covers agent inference;
# scoring runs on a separate proxy endpoint that never reaches this relay.
COST_METER = CostMeter()


class AgentBudget:
    """Per-agent inference budget, keyed by the per-problem token Kata embeds in
    the inference URL (``/j/<token>/inference``).

    Each key -- one agent working one problem -- accrues its own call count and
    input-token and output-token totals independently, so problems scored
    *concurrently* (each with a distinct token) never disturb one another's
    budget. Keying on the token (not the network source) is what makes this
    correct even though every agent reaches the relay from the same gateway
    address.

    The budget is a *cap*, never a quota: the relay only ever counts and refuses the
    agent's own calls, it never issues one. An agent that calls the model once is
    charged for one call; the limits only bite once the agent itself tries to exceed
    them.
    """

    # Bound the number of tracked keys so a long-lived relay cannot leak memory
    # across many rounds. Tokens are unique per problem and never reused, so
    # evicting the oldest key is safe -- it will never be seen again.
    MAX_TRACKED_KEYS = 8192

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: OrderedDict[str, dict[str, int]] = OrderedDict()

    def _bucket(self, key: str) -> dict[str, int]:
        bucket = self._by_key.get(key)
        if bucket is None:
            bucket = {"input_tokens": 0, "tokens": 0, "calls": 0}
            self._by_key[key] = bucket
            while len(self._by_key) > self.MAX_TRACKED_KEYS:
                self._by_key.popitem(last=False)
        return bucket

    def allow(self, key: str) -> tuple[bool, str | None]:
        with self._lock:
            bucket = self._bucket(key)
            max_calls = resolve_agent_call_budget()
            max_input_tokens = resolve_agent_input_token_budget()
            max_tokens = resolve_agent_token_budget()
            if max_calls and bucket["calls"] >= max_calls:
                return False, f"inference call budget ({max_calls}) exhausted for this problem"
            if max_input_tokens and bucket["input_tokens"] >= max_input_tokens:
                return False, (
                    f"input-token budget ({max_input_tokens}) exhausted for this problem"
                )
            if max_tokens and bucket["tokens"] >= max_tokens:
                return False, f"output-token budget ({max_tokens}) exhausted for this problem"
            return True, None

    def record(self, key: str, input_tokens: int, output_tokens: int) -> None:
        with self._lock:
            bucket = self._bucket(key)
            bucket["input_tokens"] += input_tokens
            bucket["tokens"] += output_tokens
            bucket["calls"] += 1

    def reset(self) -> None:
        with self._lock:
            self._by_key.clear()


AGENT_BUDGET = AgentBudget()


def pin_model_in_body(body: bytes, model: str, max_output_tokens: int = 0) -> bytes:
    """Apply the explicit legacy operator-funded request policy.

    A body we cannot read as a JSON object is returned untouched: the upstream
    proxy is the authority on request validity. For JSON objects, it pins the
    model, removes sampling controls, and clamps output tokens. Default
    miner-funded forwarding never calls this function.
    """
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return body
    if not isinstance(payload, dict):
        return body
    payload["model"] = model
    for field in FORBIDDEN_SAMPLING_FIELDS:
        payload.pop(field, None)
    if max_output_tokens > 0:
        # Force max_tokens to exactly the ceiling: raise a too-small request so the
        # reasoning model has room to think AND answer, and clamp a too-large one
        # so a single call can't run away (agents were observed requesting ~82k).
        payload["max_tokens"] = max_output_tokens
    return json.dumps(payload).encode("utf-8")


class MinerInferenceRelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- request entry points -------------------------------------------------
    def do_GET(self) -> None:
        path = self._path_without_query()
        if path == HEALTH_PATH:
            payload = {
                "status": "ok",
                "inference_policy": (
                    "operator-pinned" if platform_policy_enforced() else "miner-controlled"
                ),
            }
            if platform_policy_enforced():
                payload["pinned_model"] = resolve_pinned_model()
            self._send_json(200, payload)
            return
        if path == COST_PATH:
            self._send_json(200, COST_METER.snapshot(resolve_price_input(), resolve_price_output()))
            return
        self._forward("GET")

    def do_POST(self) -> None:
        path = self._path_without_query()
        if path == COST_RESET_PATH:
            self._read_body()  # drain any body so the connection stays consistent
            if not self._admin_authorized():
                self._send_json(403, {"status": "error", "detail": "admin token required"})
                return
            COST_METER.reset()
            self._send_json(200, {"status": "reset"})
            return
        if path == UPSTREAM_CHECK_PATH:
            if not self._admin_authorized():
                self._read_body()
                self._send_json(403, {"status": "error", "detail": "admin token required"})
                return
            self._handle_upstream_check()
            return
        self._forward("POST")

    def _handle_upstream_check(self) -> None:
        """Send one small diagnostic request upstream and report whether it worked.

        Returns 200 with ``{"ok": bool, "status": <upstream status>, "detail": ...}``
        so a caller can decide whether inference is usable without parsing HTTP
        errors. The request stays small so this remains a cheap operator check.
        """
        self._read_body()  # drain any body the caller sent
        # This diagnostic uses the configured legacy model when one exists; it does
        # not alter ordinary miner requests.
        api_key = self._inference_api_key()
        pinned_model = resolve_pinned_model(api_key)
        probe_body = json.dumps(
            {
                "model": pinned_model,
                "messages": [{"role": "user", "content": "Reply with the single word OK."}],
                "max_tokens": HEALTHCHECK_MAX_TOKENS,
            }
        ).encode()
        try:
            request = self._build_upstream_request(
                api_key=api_key,
                body=probe_body,
                upstream_path=INFERENCE_PATH,
                method="POST",
            )
        except RelayConfigurationError as error:
            self._send_json(200, {"ok": False, "status": 0, "detail": str(error)})
            return
        try:
            with urlopen(request, timeout=min(resolve_timeout(), 60.0)) as response:
                self._send_json(
                    200, {"ok": 200 <= response.status < 300, "status": response.status}
                )
        except HTTPError as error:
            try:
                detail = (error.read()[:300] or b"").decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - detail is best-effort
                detail = ""
            self._send_json(200, {"ok": False, "status": error.code, "detail": detail})
        except URLError as error:
            self._send_json(
                200,
                {"ok": False, "status": 0, "detail": f"could not reach upstream: {error.reason}"},
            )

    # -- forwarding -----------------------------------------------------------
    def _forward(self, method: str) -> None:
        body = self._read_body()
        path = self._path_without_query()
        query = self.path[len(path) :]
        # Agents call `<INFERENCE_API>/inference`, and Kata sets INFERENCE_API to
        # `.../j/<token>` so each problem carries its own budget key. Accept both
        # the tokenized path and a bare /inference (which shares a "default" key).
        budget_key = "default"
        upstream_path = self.path
        if method == "POST" and path.startswith("/j/") and path.endswith(INFERENCE_PATH):
            budget_key = path[len("/j/") : -len(INFERENCE_PATH)].strip("/") or "default"
            upstream_path = INFERENCE_PATH + query
            is_inference = True
        else:
            is_inference = method == "POST" and path == INFERENCE_PATH
        if not is_inference:
            self._send_json(
                404,
                {
                    "status": "error",
                    "reason": "Only POST /inference and relay-local endpoints are allowed.",
                },
            )
            return

        api_key = self._inference_api_key()
        if platform_policy_enforced():
            # Legacy validator-funded mode only: prevent an untrusted agent from
            # spending the operator's budget on a different provider/model.
            allowed, reason = AGENT_BUDGET.allow(budget_key)
            if not allowed:
                self._send_json(429, {"status": "error", "detail": f"inference budget: {reason}"})
                return
            body = pin_model_in_body(
                body,
                resolve_pinned_model(api_key),
                resolve_max_output_tokens(),
            )

        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _SKIP_REQUEST_HEADERS
        }
        try:
            request = self._build_upstream_request(
                api_key=api_key,
                body=body,
                upstream_path=upstream_path,
                method=method,
                proxy_headers=headers,
            )
        except RelayConfigurationError as error:
            self._send_json(502, {"detail": str(error)})
            return
        try:
            with urlopen(request, timeout=resolve_timeout()) as response:
                response_body = response.read()
                if is_inference and 200 <= response.status < 300:
                    input_tokens, output_tokens, _ = extract_usage(response_body)
                    self._meter(response_body)
                    if platform_policy_enforced():
                        AGENT_BUDGET.record(budget_key, input_tokens, output_tokens)
                self._relay_response(response.status, response.headers.items(), response_body)
        except HTTPError as error:
            # Upstream returned a real HTTP error (4xx/5xx); pass it through verbatim.
            self._relay_response(error.code, error.headers.items(), error.read())
        except URLError as error:
            self._send_json(502, {"detail": f"relay could not reach upstream: {error.reason}"})

    def _meter(self, response_body: bytes) -> None:
        input_tokens, output_tokens, cached_tokens = extract_usage(response_body)
        if input_tokens or output_tokens:
            COST_METER.add(input_tokens, output_tokens, cached_tokens)

    def _build_upstream_request(
        self,
        *,
        api_key: str,
        body: bytes,
        upstream_path: str,
        method: str,
        proxy_headers: dict[str, str] | None = None,
    ) -> Request:
        direct_provider = resolve_direct_provider(api_key)
        if direct_provider is not None:
            return Request(
                direct_provider.upstream,
                data=body if body else None,
                headers={
                    "Content-Type": "application/json",
                    direct_provider.auth_header: self._render_direct_auth_value(
                        direct_provider.auth_value_template,
                        api_key,
                    ),
                },
                method=method,
            )

        headers = proxy_headers or {"Content-Type": "application/json"}
        if api_key:
            headers["x-inference-api-key"] = api_key
        return Request(
            resolve_upstream() + upstream_path,
            data=body if body else None,
            headers=headers,
            method=method,
        )

    def _render_direct_auth_value(self, template: str, api_key: str) -> str:
        if "{api_key}" not in template:
            raise RelayConfigurationError(
                "KATA_RELAY_DIRECT_AUTH_VALUE_TEMPLATE must include {api_key}"
            )
        try:
            return template.format(api_key=api_key)
        except (KeyError, IndexError, ValueError) as error:
            raise RelayConfigurationError(
                "KATA_RELAY_DIRECT_AUTH_VALUE_TEMPLATE must use {api_key}"
            ) from error

    def _relay_response(self, status: int, header_items, body: bytes) -> None:
        self.send_response(status)
        for key, value in header_items:
            if key.lower() in _SKIP_RESPONSE_HEADERS:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -- helpers --------------------------------------------------------------
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _path_without_query(self) -> str:
        return self.path.split("?", 1)[0]

    def _inference_api_key(self) -> str:
        return self.headers.get("x-inference-api-key", "").strip()

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _admin_authorized(self) -> bool:
        expected = resolve_admin_token()
        if not expected:
            return False
        supplied = self.headers.get(ADMIN_TOKEN_HEADER, "")
        return compare_digest(supplied, expected)

    def log_message(self, *_args) -> None:
        # Silence per-request logging; inference bodies could be large/noisy.
        return


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), MinerInferenceRelayHandler)
    server.daemon_threads = True
    return server


def main() -> int:
    host = os.environ.get("KATA_RELAY_HOST", "0.0.0.0")
    port = int(os.environ.get("KATA_RELAY_PORT", "8000"))
    server = build_server(host, port)
    print(
        f"SN60 miner-funded inference relay listening on {host}:{port} -> {resolve_upstream()} "
        f"(policy={'operator-pinned' if platform_policy_enforced() else 'miner-controlled'}; "
        f"cost at GET {COST_PATH}, "
        f"zero it with POST {COST_RESET_PATH})",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
