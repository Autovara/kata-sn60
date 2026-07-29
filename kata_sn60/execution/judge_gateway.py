"""Kata-owned metering gateway for validator-paid judge traffic (plan item 1).

The SN60 scorer bills the VALIDATOR's ``CHUTES_API_KEY``: ``scorer.prompt`` posts to
``{PROXY_URL}/inference`` with no client timeout, and the Bitsec proxy behind it retries up to
``MAX_RETRIES`` upstream attempts at ``TIMEOUT`` seconds each. Nothing on that path counts calls,
counts tokens, or refuses one. Only TEE runs were ever budgeted, so judge spend had no ceiling.

``PROXY_URL`` is injected by Kata (``sn60_bitsec.build_default_evaluation_hook``), so this module
takes that seam: it stands a loopback gateway in front of the real proxy and hands the scorer its
address. Every judge call then passes through a place Kata owns, WITHOUT modifying the pinned
upstream tree (an edit there is a ``verify_snapshot`` finding by design, and the proxy image's
build path was never established).

Two layers, deliberately split:

* ``JudgeMeter`` -- the caps, as pure lock-guarded state. Reserve-then-settle per call, mirroring
  the platform's day budget (``kata_bot.budget``): a call reserves its WORST CASE before it is
  forwarded and settles its ACTUAL after, so a crash or a hang mid-call leaves the budget
  conservatively consumed rather than unrecorded. No sockets, so the caps are testable directly.
* ``JudgeGateway`` -- the loopback HTTP forwarder that applies the meter to ``POST /inference``.

Every cap is HARD, in the sense the platform's hard-cost contract requires -- a bound that holds
however the scorer behaves, not an average:

* ``max_calls`` bounds forwarded requests.
* ``max_request_chars`` bounds the prompt bytes of ONE call, so input tokens per call are bounded.
* ``max_output_tokens_per_call`` is INJECTED into the forwarded payload, so output tokens per call
  are bounded by the provider itself, not by trust in the scorer's config.

Together those bound total tokens (and so spend) for the whole challenge; ``worst_case_usage``
derives that product for the reservation.

REFUSALS ARE NOT SILENT. ``scorer.find_match_in_results`` catches every per-chunk exception and
continues to the next chunk, so a refused call does not stop the scorer -- it would publish a
QUIETLY DEGRADED score instead. A refusal is therefore recorded, and the caller must fail the
evaluation closed when ``JudgeUsage.refusals`` is non-zero rather than scoring the partial result.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

#: Conservative floor for characters-per-token when converting a character cap into a token
#: bound. Real tokenizers average ~4 chars/token on English prose and code; 1.0 assumes the
#: pathological case of one token per character so the derived bound can never UNDERSTATE the
#: tokens a request can buy. Understating is the dangerous direction: the reservation would be
#: smaller than the actual spend, which settles as a cost-accounting violation and freezes the lane.
CHARS_PER_TOKEN_FLOOR = 1.0

#: Per-request ceiling on the forwarded call. The upstream proxy's own budget is
#: ``MAX_RETRIES * TIMEOUT`` (~25 min) with no client-side deadline at all; this is the deadline
#: the scorer never sets.
DEFAULT_PER_REQUEST_TIMEOUT_SECONDS = 180.0

#: Serialized prompt bytes one judge call may carry. The scorer chunks candidates
#: (``chunk_size=10``) and truncates descriptions (``desc_max_chars=800``), so a real evaluation
#: prompt is far under this; it exists to make "input tokens per call" a bound rather than a habit.
DEFAULT_MAX_REQUEST_CHARS = 200_000

#: Completion cap injected into every forwarded payload.
DEFAULT_MAX_OUTPUT_TOKENS_PER_CALL = 4096


class JudgeBudgetError(RuntimeError):
    """The gateway cannot meter safely (misconfigured caps). Fail closed: do not spend."""


class JudgeProtocolError(JudgeBudgetError):
    """The scorer used the gateway without an active, validator-issued attribution scope."""


@dataclass(frozen=True)
class JudgeUsage:
    """What a challenge's judge phase actually consumed. Settled into the day budget and published
    in ``challenge_result.json`` -- the answer to "what did scoring this duel cost"."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    spend_usd: float = 0.0
    #: Calls the gateway refused. Non-zero means the score is INCOMPLETE and must not be published.
    refusals: int = 0
    #: Why the first refusal happened. The first one is the informative one; later refusals are
    #: usually the scorer walking into the same closed door for every remaining chunk.
    first_refusal_reason: str = ""
    #: Calls forwarded that failed upstream (timeout, connection, non-2xx). Distinct from a
    #: refusal: the money may well have been spent, we just did not get a usable answer.
    upstream_errors: int = 0
    #: Requests whose scorer attribution or wire format was invalid. Any non-zero value is
    #: challenge-fatal: an unattributed request cannot safely be assigned to one project.
    protocol_errors: int = 0
    first_protocol_error: str = ""

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def as_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "total_tokens": self.total_tokens,
            "spend_usd": round(self.spend_usd, 6),
            "refusals": self.refusals,
            "first_refusal_reason": self.first_refusal_reason,
            "upstream_errors": self.upstream_errors,
            "protocol_errors": self.protocol_errors,
            "first_protocol_error": self.first_protocol_error,
        }


@dataclass(frozen=True)
class JudgeBudgetLimits:
    """Per-challenge caps on validator-paid judge traffic. ``None`` is UNCONSTRAINED for that
    dimension, matching ``kata_bot.budget``'s convention that an unset cap is not a zero cap."""

    max_calls: int | None = None
    max_total_tokens: int | None = None
    max_spend_usd: float | None = None
    #: Prices for the spend cap and for the settled ``spend_usd``. Required only when
    #: ``max_spend_usd`` is set -- a spend cap with no price is a cap nothing can evaluate.
    usd_per_million_input_tokens: float | None = None
    usd_per_million_output_tokens: float | None = None
    per_request_timeout_seconds: float = DEFAULT_PER_REQUEST_TIMEOUT_SECONDS
    max_request_chars: int = DEFAULT_MAX_REQUEST_CHARS
    max_output_tokens_per_call: int = DEFAULT_MAX_OUTPUT_TOKENS_PER_CALL
    #: Wall-clock ceiling for the WHOLE challenge's judge phase. The existing
    #: ``KATA_SN60_EVALUATION_TIMEOUT_SECONDS`` bounds one project subprocess; with several
    #: projects (concurrency 3) the challenge-wide total was bounded by nothing.
    challenge_deadline_seconds: float | None = None

    def __post_init__(self) -> None:
        for name in ("max_calls", "max_total_tokens"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or value < 0):
                raise JudgeBudgetError(f"{name} must be a non-negative int, got {value!r}")
        if self.max_spend_usd is not None:
            if self.max_spend_usd < 0:
                raise JudgeBudgetError(
                    f"max_spend_usd must be non-negative, got {self.max_spend_usd!r}"
                )
            missing = [
                name
                for name in ("usd_per_million_input_tokens", "usd_per_million_output_tokens")
                if getattr(self, name) is None
            ]
            if missing:
                # Fail closed rather than enforce a dollar cap against tokens we cannot price.
                raise JudgeBudgetError(
                    f"max_spend_usd is set but {', '.join(missing)} is not; "
                    "a spend cap needs a price"
                )
        for name in (
            "per_request_timeout_seconds",
            "max_request_chars",
            "max_output_tokens_per_call",
        ):
            if getattr(self, name) <= 0:
                raise JudgeBudgetError(f"{name} must be positive, got {getattr(self, name)!r}")
        if self.challenge_deadline_seconds is not None and self.challenge_deadline_seconds <= 0:
            raise JudgeBudgetError(
                "challenge_deadline_seconds must be positive, got "
                f"{self.challenge_deadline_seconds!r}"
            )

    def worst_case_usage(self) -> dict[str, float]:
        """The reservation: the most this challenge's judge phase can consume, per dimension.

        Derived from the caps the gateway ENFORCES, so the settled actual can never exceed it.
        Raises when ``max_calls`` is unset, because every other dimension's bound is a multiple of
        it -- without a call ceiling there is no finite worst case to reserve, and the platform
        must defer rather than run a paid path against a cap nothing can enforce.
        """
        if self.max_calls is None:
            raise JudgeBudgetError("cannot bound judge usage without max_calls")
        input_ceiling = self.max_calls * (self.max_request_chars / CHARS_PER_TOKEN_FLOOR)
        output_ceiling = self.max_calls * self.max_output_tokens_per_call
        tokens = input_ceiling + output_ceiling
        if self.max_total_tokens is not None:
            # The explicit cap is enforced too, so the true worst case is whichever binds first.
            tokens = min(tokens, float(self.max_total_tokens))
        bounds = {"inference_calls": float(self.max_calls), "tokens": float(tokens)}
        if self.max_spend_usd is not None:
            priced = _price(
                input_tokens=input_ceiling,
                output_tokens=output_ceiling,
                limits=self,
            )
            bounds["spend_usd"] = min(priced, float(self.max_spend_usd))
        return bounds


def _price(*, input_tokens: float, output_tokens: float, limits: JudgeBudgetLimits) -> float:
    """Dollar cost of a token count. Cached tokens are billed at the FULL input rate: providers
    discount them, so charging full price over-states spend, and over-stating is the safe
    direction for a ceiling."""
    per_in = limits.usd_per_million_input_tokens or 0.0
    per_out = limits.usd_per_million_output_tokens or 0.0
    return (input_tokens * per_in + output_tokens * per_out) / 1_000_000.0


#: Per-challenge judge caps, read from the lane env. Deliberately SEPARATE from the platform's
#: ``KATA_SUBNET_BUDGET_*`` vars, which are per-lane PER-DAY ceilings: these bound ONE challenge,
#: and the per-challenge worst case is what ``capacity_estimate`` reserves against the day cap.
JUDGE_ENV = {
    "max_calls": "KATA_SN60_JUDGE_MAX_CALLS",
    "max_total_tokens": "KATA_SN60_JUDGE_MAX_TOKS",
    "max_spend_usd": "KATA_SN60_JUDGE_MAX_SPEND_USD",
    "usd_per_million_input_tokens": "KATA_SN60_JUDGE_USD_PER_MTOK_INPUT",
    "usd_per_million_output_tokens": "KATA_SN60_JUDGE_USD_PER_MTOK_OUTPUT",
    "per_request_timeout_seconds": "KATA_SN60_JUDGE_REQUEST_TIMEOUT_SECONDS",
    "max_request_chars": "KATA_SN60_JUDGE_MAX_REQUEST_CHARS",
    "max_output_tokens_per_call": "KATA_SN60_JUDGE_MAX_OUTPUT_TOKS",
    "challenge_deadline_seconds": "KATA_SN60_JUDGE_DEADLINE_SECONDS",
}

_INT_FIELDS = frozenset(
    {"max_calls", "max_total_tokens", "max_request_chars", "max_output_tokens_per_call"}
)


def judge_limits_from_env(env: dict[str, str] | None = None) -> JudgeBudgetLimits | None:
    """The lane's per-challenge judge caps, or ``None`` when the operator configured no ceiling.

    ``None`` means UNMETERED -- the pre-existing behaviour, kept so the gateway can be rolled out
    without forcing every deployment to pick numbers on the same day. ``KATA_SN60_JUDGE_MAX_CALLS``
    is what turns metering on, because it is the dimension every other bound is a multiple of;
    setting any other cap without it is a configuration error rather than a partial ceiling.
    """
    import os

    env = dict(os.environ if env is None else env)
    raw = {
        name: (env.get(var) or "").strip()
        for name, var in JUDGE_ENV.items()
        if (env.get(var) or "").strip()
    }
    if not raw:
        return None
    if "max_calls" not in raw:
        configured = ", ".join(sorted(JUDGE_ENV[field] for field in raw))
        raise JudgeBudgetError(
            f"{configured} set without {JUDGE_ENV['max_calls']}; a judge budget needs a call "
            "ceiling to be a bound at all"
        )
    kwargs: dict[str, Any] = {}
    for field_name, value in raw.items():
        var = JUDGE_ENV[field_name]
        try:
            kwargs[field_name] = int(value) if field_name in _INT_FIELDS else float(value)
        except ValueError as exc:
            raise JudgeBudgetError(f"{var} is not a number: {value!r}") from exc
    return JudgeBudgetLimits(**kwargs)


class JudgeBudgetExceeded(Exception):
    """One more call would breach a cap (or the deadline has passed). The gateway refuses it."""

    def __init__(self, dimension: str, detail: str = ""):
        super().__init__(f"judge budget exceeded: {dimension} {detail}".strip())
        self.dimension = dimension


@dataclass
class _Hold:
    """A reserved-but-not-settled call: the worst case charged at reserve time."""

    input_tokens: float
    output_tokens: float
    scope: str = ""


class JudgeMeter:
    """The caps, as lock-guarded state. Reserve worst case -> forward -> settle actual.

    Concurrency is real here: SN60 evaluates projects in parallel
    (``KATA_SN60_PROJECT_CONCURRENCY``, default 3), each an independent scorer subprocess pointed
    at the same gateway, so several reservations are in flight at once. Holding the worst case for
    each in-flight call is what makes the ceiling hold under that concurrency -- settling only at
    the end would let N concurrent calls each pass a check the others had already spent.
    """

    def __init__(self, limits: JudgeBudgetLimits, *, clock=time.monotonic) -> None:
        self._limits = limits
        self._clock = clock
        self._lock = threading.Lock()
        self._started_at = clock()
        self._usage = JudgeUsage()
        self._usage_by_scope: dict[str, JudgeUsage] = {}
        self._holds: dict[int, _Hold] = {}
        self._next_hold_id = 0

    @property
    def limits(self) -> JudgeBudgetLimits:
        return self._limits

    def usage(self, *, scope: str | None = None) -> JudgeUsage:
        with self._lock:
            return self._usage if scope is None else self._usage_by_scope.get(scope, JudgeUsage())

    def deadline_remaining(self) -> float | None:
        """Seconds left on the challenge-wide deadline, or ``None`` when unconstrained."""
        if self._limits.challenge_deadline_seconds is None:
            return None
        return self._limits.challenge_deadline_seconds - (self._clock() - self._started_at)

    def _held(self) -> tuple[float, float]:
        held_in = sum(h.input_tokens for h in self._holds.values())
        held_out = sum(h.output_tokens for h in self._holds.values())
        return held_in, held_out

    def reserve(self, *, request_chars: int, scope: str = "") -> int:
        """Charge one call's WORST CASE and return a hold id. Raises ``JudgeBudgetExceeded`` if any
        cap (or the deadline) has no headroom -- the caller must then refuse, not forward."""
        limits = self._limits
        if request_chars > limits.max_request_chars:
            # Refused BEFORE any spend: an oversized prompt is exactly the case the per-call input
            # bound exists for, so let it fail rather than silently buy an unbounded call.
            raise JudgeBudgetExceeded(
                "request_chars", f"{request_chars} > {limits.max_request_chars}"
            )
        remaining = self.deadline_remaining()
        if remaining is not None and remaining <= 0:
            raise JudgeBudgetExceeded(
                "challenge_deadline", f"{limits.challenge_deadline_seconds}s elapsed"
            )
        want_in = request_chars / CHARS_PER_TOKEN_FLOOR
        want_out = float(limits.max_output_tokens_per_call)
        with self._lock:
            usage = self._usage
            held_in, held_out = self._held()
            if limits.max_calls is not None:
                projected = usage.calls + len(self._holds) + 1
                if projected > limits.max_calls:
                    raise JudgeBudgetExceeded("max_calls", f"{projected} > {limits.max_calls}")
            if limits.max_total_tokens is not None:
                projected_tokens = (
                    usage.total_tokens + held_in + held_out + want_in + want_out
                )
                if projected_tokens > limits.max_total_tokens:
                    raise JudgeBudgetExceeded(
                        "max_total_tokens", f"{projected_tokens:.0f} > {limits.max_total_tokens}"
                    )
            if limits.max_spend_usd is not None:
                projected_spend = usage.spend_usd + _price(
                    input_tokens=held_in + want_in,
                    output_tokens=held_out + want_out,
                    limits=limits,
                )
                if projected_spend > limits.max_spend_usd:
                    raise JudgeBudgetExceeded(
                        "max_spend_usd", f"{projected_spend:.4f} > {limits.max_spend_usd}"
                    )
            hold_id = self._next_hold_id
            self._next_hold_id += 1
            self._holds[hold_id] = _Hold(
                input_tokens=want_in,
                output_tokens=want_out,
                scope=scope,
            )
            return hold_id

    def settle(
        self,
        hold_id: int,
        *,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int,
        upstream_error: bool = False,
    ) -> None:
        """Replace a hold with the call's ACTUAL usage. Idempotent: settling an unknown or
        already-settled hold is a no-op, so a retry or a double-finally cannot double-charge."""
        with self._lock:
            hold = self._holds.pop(hold_id, None)
            if hold is None:
                return
            # The provider is expected to honour max_tokens, but its receipt is authoritative. If
            # it reports more than the reservation, keep the real amount and flag the evaluation;
            # the outer budget then detects actual > estimate and freezes rather than hiding spend.
            upstream_error = upstream_error or (
                input_tokens > hold.input_tokens or output_tokens > hold.output_tokens
            )
            spend = _price(
                input_tokens=float(input_tokens),
                output_tokens=float(output_tokens),
                limits=self._limits,
            )
            for scope in (None, hold.scope):
                usage = (
                    self._usage
                    if scope is None
                    else self._usage_by_scope.get(scope, JudgeUsage())
                )
                updated = replace(
                    usage,
                    calls=usage.calls + 1,
                    input_tokens=usage.input_tokens + int(input_tokens),
                    output_tokens=usage.output_tokens + int(output_tokens),
                    cached_tokens=usage.cached_tokens + int(cached_tokens),
                    spend_usd=usage.spend_usd + spend,
                    upstream_errors=usage.upstream_errors + (1 if upstream_error else 0),
                )
                if scope is None:
                    self._usage = updated
                else:
                    self._usage_by_scope[scope] = updated

    def settle_worst_case(self, hold_id: int) -> None:
        """Settle a call whose real usage is UNKNOWN (an unparseable response, a timeout after the
        request left) at the full reserved amount. Fail closed: we cannot prove the provider did
        not bill us, so the budget keeps the conservative charge."""
        with self._lock:
            hold = self._holds.get(hold_id)
            if hold is None:
                return
            reserved_in, reserved_out = int(hold.input_tokens), int(hold.output_tokens)
        self.settle(
            hold_id,
            input_tokens=reserved_in,
            output_tokens=reserved_out,
            cached_tokens=0,
            upstream_error=True,
        )

    def settle_all_holds_worst_case(self) -> None:
        """Conservatively close every request still in flight when the gateway stops.

        Handler threads are daemonized so a wedged provider cannot wedge challenge shutdown. A
        request may nevertheless have left the host and been billed; converting its hold before
        publishing usage prevents a late handler from being omitted from settlement.
        """

        with self._lock:
            hold_ids = list(self._holds)
        for hold_id in hold_ids:
            self.settle_worst_case(hold_id)

    def record_refusal(self, reason: str, *, scope: str = "") -> None:
        with self._lock:
            for current_scope in (None, scope):
                usage = (
                    self._usage
                    if current_scope is None
                    else self._usage_by_scope.get(current_scope, JudgeUsage())
                )
                updated = replace(
                    usage,
                    refusals=usage.refusals + 1,
                    first_refusal_reason=usage.first_refusal_reason or reason,
                )
                if current_scope is None:
                    self._usage = updated
                else:
                    self._usage_by_scope[current_scope] = updated

    def record_protocol_error(self, reason: str, *, scope: str | None = None) -> None:
        """Record an invalid scorer request.

        Missing and unknown scopes are deliberately global-only: assigning them to a caller-chosen
        bucket is the fail-open this guard exists to prevent. A known scope is also updated so the
        responsible evaluation can fail immediately, while the global count remains the
        authoritative challenge-level backstop.
        """

        with self._lock:
            scopes: tuple[str | None, ...] = (None,) if scope is None else (None, scope)
            for current_scope in scopes:
                usage = (
                    self._usage
                    if current_scope is None
                    else self._usage_by_scope.get(current_scope, JudgeUsage())
                )
                updated = replace(
                    usage,
                    protocol_errors=usage.protocol_errors + 1,
                    first_protocol_error=usage.first_protocol_error or reason,
                )
                if current_scope is None:
                    self._usage = updated
                else:
                    self._usage_by_scope[current_scope] = updated


class _Handler(BaseHTTPRequestHandler):
    """Forwards ``POST /inference`` through the meter. Everything else is 404: the gateway is not
    a general proxy, and the scorer's metrics endpoints talk to the real proxy directly."""

    protocol_version = "HTTP/1.1"
    server_version = "KataJudgeGateway/1"

    @property
    def _gateway(self) -> "JudgeGateway":
        return self.server.gateway  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        # BaseHTTPRequestHandler logs every request to stderr, which lands in the scorer's captured
        # output and gets parsed for the result JSON. Route it to the gateway's own log instead.
        self._gateway.log_lines.append(fmt % args)

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's required spelling
        if self.path.rstrip("/") != "/inference":
            self._respond(404, {"detail": f"unknown endpoint {self.path}"})
            return
        scope = self._gateway.authorize_scope(self.headers.get("x-job-run-id"))
        if scope is None:
            # Do not buffer a request whose spend cannot be attributed to an active evaluation.
            self.close_connection = True
            self._respond(403, {"detail": "invalid or inactive x-job-run-id"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._gateway.meter.record_protocol_error("invalid Content-Length", scope=scope)
            self.close_connection = True
            self._respond(400, {"detail": "invalid Content-Length"})
            return
        if length < 0:
            self._gateway.meter.record_protocol_error("invalid Content-Length", scope=scope)
            self.close_connection = True
            self._respond(400, {"detail": "invalid Content-Length"})
            return
        if length > self._gateway.meter.limits.max_request_chars:
            reason = (
                "judge budget exceeded: request_chars "
                f"{length} > {self._gateway.meter.limits.max_request_chars}"
            )
            self._gateway.meter.record_refusal(reason, scope=scope)
            # Do not read or buffer an oversized declared body. Closing the connection prevents
            # unread bytes from being parsed as a second HTTP request.
            self.close_connection = True
            self._respond(413, {"detail": reason, "dimension": "request_chars"})
            return
        raw = self.rfile.read(length) if length > 0 else b""
        self._gateway.handle_inference(self, raw, scope=scope)


class JudgeGateway:
    """Loopback gateway the scorer is pointed at instead of the real proxy.

    Use as a context manager for one challenge; ``url`` is what belongs in the scorer's
    ``PROXY_URL``, and ``usage()`` is the settled truth for the day budget and the published
    result. Binds 127.0.0.1 on an ephemeral port: the scorer runs as a host subprocess (the
    existing default is ``http://localhost:8087``), and loopback keeps validator-paid capacity
    unreachable from the miner containers, which have their own ``INFERENCE_API`` and pay with
    their own key.
    """

    def __init__(
        self,
        *,
        upstream_url: str,
        limits: JudgeBudgetLimits,
        clock=time.monotonic,
        opener=None,
    ) -> None:
        self._upstream = upstream_url.rstrip("/")
        self._meter = JudgeMeter(limits, clock=clock)
        self._opener = opener or urllib.request.urlopen
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._scope_lock = threading.Lock()
        self._active_scopes: set[str] = set()
        self.log_lines: list[str] = []

    @property
    def meter(self) -> JudgeMeter:
        return self._meter

    def usage(self, *, scope: str | None = None) -> JudgeUsage:
        return self._meter.usage(scope=scope)

    @staticmethod
    def _canonical_scope(scope: str) -> bool:
        # Kata's synthetic job-run ids are positive signed-32-bit integers. Tight validation keeps
        # arbitrary strings (including the upstream scorer's "unknown" fallback) out of accounting.
        return (
            bool(scope)
            and len(scope) <= 10
            and scope.isascii()
            and scope.isdecimal()
            and scope[0] != "0"
            and int(scope) <= 2**31 - 1
        )

    def register_scope(self, scope: str) -> None:
        """Authorize exactly one active evaluation's deterministic job-run id."""

        if not self._canonical_scope(scope):
            self._meter.record_protocol_error(f"invalid judge scope {scope!r}")
            raise JudgeProtocolError(f"invalid judge scope {scope!r}")
        with self._scope_lock:
            if scope in self._active_scopes:
                self._meter.record_protocol_error(f"judge scope is already active: {scope}")
                raise JudgeProtocolError(f"judge scope is already active: {scope}")
            self._active_scopes.add(scope)

    def unregister_scope(self, scope: str) -> None:
        with self._scope_lock:
            self._active_scopes.discard(scope)

    def authorize_scope(self, header: str | None) -> str | None:
        """Return an active canonical scope, recording a challenge-fatal error otherwise."""

        scope = (header or "").strip()
        if not self._canonical_scope(scope):
            self._meter.record_protocol_error("missing or malformed x-job-run-id")
            return None
        with self._scope_lock:
            active = scope in self._active_scopes
        if not active:
            self._meter.record_protocol_error(f"unregistered x-job-run-id {scope}")
            return None
        return scope

    @property
    def url(self) -> str:
        if self._server is None:
            raise JudgeBudgetError("gateway is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "JudgeGateway":
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        server.gateway = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
        self._meter.settle_all_holds_worst_case()

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def final_usage(self) -> JudgeUsage:
        """Stop intake, account every in-flight hold, and return immutable settled usage."""

        self.close()
        self._meter.settle_all_holds_worst_case()
        usage = self._meter.usage()
        if usage.protocol_errors:
            raise JudgeProtocolError(
                "judge attribution protocol failed "
                f"{usage.protocol_errors} time(s): {usage.first_protocol_error}"
            )
        return usage

    def handle_inference(self, handler: _Handler, raw: bytes, *, scope: str) -> None:
        try:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload is not a JSON object")
        except (ValueError, UnicodeDecodeError) as exc:
            self._meter.record_protocol_error(
                f"invalid inference payload: {exc}",
                scope=scope,
            )
            handler.close_connection = True
            handler._respond(400, {"detail": f"invalid inference payload: {exc}"})
            return

        # Cap the completion at the provider, so output tokens per call are bounded by the
        # request we actually send rather than by trusting the scorer's own settings.
        requested = payload.get("max_tokens")
        ceiling = self._meter.limits.max_output_tokens_per_call
        payload["max_tokens"] = (
            min(int(requested), ceiling)
            if isinstance(requested, int) and requested > 0
            else ceiling
        )
        body = json.dumps(payload).encode("utf-8")

        try:
            hold_id = self._meter.reserve(request_chars=len(body), scope=scope)
        except JudgeBudgetExceeded as exc:
            self._meter.record_refusal(str(exc), scope=scope)
            # 429 is what the scorer's own error path understands; it will swallow it and move to
            # the next chunk, which is precisely why the refusal COUNT (not this response) is what
            # the caller must fail the evaluation on.
            handler._respond(429, {"detail": str(exc), "dimension": exc.dimension})
            return

        timeout = self._meter.limits.per_request_timeout_seconds
        remaining = self._meter.deadline_remaining()
        if remaining is not None:
            # Never let one request outlive the challenge-wide deadline.
            timeout = min(timeout, max(remaining, 0.001))

        forward_headers = {"Content-Type": "application/json"}
        for name in ("x-inference-api-key", "x-agent-id", "x-job-run-id", "x-request-phase"):
            value = handler.headers.get(name)
            if value is not None:
                forward_headers[name] = value

        request = urllib.request.Request(
            f"{self._upstream}/inference", data=body, headers=forward_headers, method="POST"
        )
        try:
            with self._opener(request, timeout=timeout) as response:
                status = response.status
                response_body = response.read()
        except urllib.error.HTTPError as exc:
            # The upstream answered with an error. It may still have billed us (the proxy retries
            # internally and a 502 can follow paid attempts), so settle the worst case.
            self._meter.settle_worst_case(hold_id)
            handler._respond(exc.code, {"detail": f"upstream error: {exc.reason}"})
            return
        except Exception as exc:  # noqa: BLE001 - timeout, connection reset, malformed response
            self._meter.settle_worst_case(hold_id)
            handler._respond(504, {"detail": f"upstream request failed: {exc}"})
            return

        usage = _usage_from_response(response_body)
        if usage is None:
            self._meter.settle_worst_case(hold_id)
        else:
            self._meter.settle(hold_id, **usage)

        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(response_body)))
        handler.end_headers()
        handler.wfile.write(response_body)


def _usage_from_response(body: bytes) -> dict[str, int] | None:
    """The call's real token usage, or ``None`` when the response cannot be read as usage (the
    caller then settles the worst case rather than assuming zero)."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    # A present-but-partial receipt is not evidence of zero spend. The flattened proxy fields
    # default to zero when upstream omits usage, so only the canonical required usage fields are
    # authoritative enough to settle below the reservation.
    if "prompt_tokens" not in usage or "completion_tokens" not in usage:
        return None
    details = usage.get("prompt_tokens_details")
    cached = details.get("cached_tokens", 0) if isinstance(details, dict) else 0
    values = (usage["prompt_tokens"], usage["completion_tokens"], cached)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        return None
    if any(value < 0 for value in values):
        return None
    return {
        "input_tokens": usage["prompt_tokens"],
        "output_tokens": usage["completion_tokens"],
        "cached_tokens": cached,
    }
