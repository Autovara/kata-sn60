"""Tests for the validator-paid judge budget gateway (kata_sn60.execution.judge_gateway).

The meter is exercised directly (no sockets) so each cap is asserted on its own; the gateway is
exercised over a real loopback socket with a fake upstream, so the forwarding, the injected
completion cap and the refusal path are tested as the scorer will actually meet them.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from kata_sn60.execution.judge_gateway import (
    CHARS_PER_TOKEN_FLOOR,
    JudgeBudgetError,
    JudgeBudgetExceeded,
    JudgeBudgetLimits,
    JudgeGateway,
    JudgeMeter,
)


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _usage_body(prompt: int = 100, completion: int = 50, cached: int = 10) -> bytes:
    return json.dumps(
        {
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": prompt,
                "completion_tokens": completion,
                "prompt_tokens_details": {"cached_tokens": cached},
            },
        }
    ).encode("utf-8")


# --- limits validation -----------------------------------------------------------------------


def test_a_spend_cap_without_a_price_is_refused_at_construction() -> None:
    with pytest.raises(JudgeBudgetError, match="needs a price"):
        JudgeBudgetLimits(max_calls=10, max_spend_usd=5.0)


def test_a_spend_cap_with_prices_is_accepted() -> None:
    limits = JudgeBudgetLimits(
        max_calls=10,
        max_spend_usd=5.0,
        usd_per_million_input_tokens=0.2,
        usd_per_million_output_tokens=0.8,
    )
    assert limits.max_spend_usd == 5.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_calls": -1},
        {"max_total_tokens": -5},
        {"per_request_timeout_seconds": 0},
        {"max_request_chars": 0},
        {"max_output_tokens_per_call": -1},
        {"challenge_deadline_seconds": 0},
    ],
)
def test_nonsense_caps_fail_closed(kwargs: dict) -> None:
    with pytest.raises(JudgeBudgetError):
        JudgeBudgetLimits(**kwargs)


# --- the reservation bound -------------------------------------------------------------------


def test_worst_case_usage_needs_a_call_ceiling_to_be_finite() -> None:
    with pytest.raises(JudgeBudgetError, match="max_calls"):
        JudgeBudgetLimits().worst_case_usage()


def test_worst_case_usage_is_the_product_of_the_enforced_per_call_caps() -> None:
    limits = JudgeBudgetLimits(max_calls=4, max_request_chars=1000, max_output_tokens_per_call=100)
    bounds = limits.worst_case_usage()
    assert bounds["inference_calls"] == 4.0
    assert bounds["tokens"] == 4 * (1000 / CHARS_PER_TOKEN_FLOOR) + 4 * 100


def test_worst_case_usage_takes_whichever_token_cap_binds_first() -> None:
    limits = JudgeBudgetLimits(
        max_calls=4, max_request_chars=1000, max_output_tokens_per_call=100, max_total_tokens=500
    )
    assert limits.worst_case_usage()["tokens"] == 500.0


# --- the caps --------------------------------------------------------------------------------


def test_the_call_ceiling_refuses_the_call_after_the_last_allowed_one() -> None:
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=2))
    for _ in range(2):
        hold = meter.reserve(request_chars=10)
        meter.settle(hold, input_tokens=1, output_tokens=1, cached_tokens=0)
    with pytest.raises(JudgeBudgetExceeded) as exc:
        meter.reserve(request_chars=10)
    assert exc.value.dimension == "max_calls"
    assert meter.usage().calls == 2


def test_in_flight_reservations_count_against_the_ceiling() -> None:
    """The concurrency case: SN60 scores projects in parallel, so several calls are outstanding at
    once. Each must hold its worst case, or N concurrent calls all pass a check the others spent."""
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=2))
    meter.reserve(request_chars=10)
    meter.reserve(request_chars=10)
    with pytest.raises(JudgeBudgetExceeded):
        meter.reserve(request_chars=10)


def test_settling_an_actual_below_the_worst_case_returns_the_headroom() -> None:
    limits = JudgeBudgetLimits(max_calls=10, max_total_tokens=1000, max_output_tokens_per_call=400)
    meter = JudgeMeter(limits)
    hold = meter.reserve(request_chars=100)  # holds 100 input + 400 output
    meter.settle(hold, input_tokens=10, output_tokens=5, cached_tokens=0)
    assert meter.usage().total_tokens == 15
    # A second call would have been refused against the hold, and is fine against the actual.
    meter.reserve(request_chars=100)


def test_the_token_ceiling_refuses_a_call_that_would_breach_it() -> None:
    meter = JudgeMeter(
        JudgeBudgetLimits(max_calls=100, max_total_tokens=500, max_output_tokens_per_call=400)
    )
    hold = meter.reserve(request_chars=50)
    meter.settle(hold, input_tokens=200, output_tokens=200, cached_tokens=0)
    with pytest.raises(JudgeBudgetExceeded) as exc:
        meter.reserve(request_chars=50)
    assert exc.value.dimension == "max_total_tokens"


def test_the_spend_ceiling_refuses_a_call_that_would_breach_it() -> None:
    limits = JudgeBudgetLimits(
        max_calls=100,
        max_spend_usd=0.001,
        usd_per_million_input_tokens=1.0,
        usd_per_million_output_tokens=1.0,
        max_output_tokens_per_call=400,
    )
    meter = JudgeMeter(limits)
    hold = meter.reserve(request_chars=100)
    meter.settle(hold, input_tokens=600, output_tokens=300, cached_tokens=0)
    assert meter.usage().spend_usd == pytest.approx(0.0009)
    with pytest.raises(JudgeBudgetExceeded) as exc:
        meter.reserve(request_chars=100)
    assert exc.value.dimension == "max_spend_usd"


def test_an_oversized_prompt_is_refused_before_it_is_forwarded() -> None:
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=10, max_request_chars=100))
    with pytest.raises(JudgeBudgetExceeded) as exc:
        meter.reserve(request_chars=101)
    assert exc.value.dimension == "request_chars"
    assert meter.usage().calls == 0


def test_the_challenge_deadline_refuses_calls_once_it_has_passed() -> None:
    clock = _FakeClock()
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=100, challenge_deadline_seconds=60), clock=clock)
    meter.settle(meter.reserve(request_chars=10), input_tokens=1, output_tokens=1, cached_tokens=0)
    clock.now = 61.0
    assert meter.deadline_remaining() == pytest.approx(-1.0)
    with pytest.raises(JudgeBudgetExceeded) as exc:
        meter.reserve(request_chars=10)
    assert exc.value.dimension == "challenge_deadline"


def test_an_unconstrained_deadline_has_no_remaining_value() -> None:
    assert JudgeMeter(JudgeBudgetLimits(max_calls=1)).deadline_remaining() is None


# --- settlement ------------------------------------------------------------------------------


def test_settling_the_same_hold_twice_does_not_double_charge() -> None:
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=10))
    hold = meter.reserve(request_chars=10)
    meter.settle(hold, input_tokens=7, output_tokens=3, cached_tokens=1)
    meter.settle(hold, input_tokens=7, output_tokens=3, cached_tokens=1)
    usage = meter.usage()
    assert (usage.calls, usage.input_tokens, usage.output_tokens) == (1, 7, 3)


def test_a_call_whose_usage_is_unknown_settles_at_the_reserved_worst_case() -> None:
    """Fail closed: we cannot prove the provider did not bill us, so the budget keeps the charge."""
    limits = JudgeBudgetLimits(max_calls=10, max_output_tokens_per_call=400)
    meter = JudgeMeter(limits)
    hold = meter.reserve(request_chars=250)
    meter.settle_worst_case(hold)
    usage = meter.usage()
    assert usage.input_tokens == int(250 / CHARS_PER_TOKEN_FLOOR)
    assert usage.output_tokens == 400
    assert usage.upstream_errors == 1


def test_a_refusal_is_recorded_with_the_first_reason() -> None:
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=1))
    meter.record_refusal("max_calls first")
    meter.record_refusal("max_calls second")
    usage = meter.usage()
    assert usage.refusals == 2
    assert usage.first_refusal_reason == "max_calls first"


def test_concurrent_reservations_never_exceed_the_ceiling() -> None:
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=20))
    granted: list[int] = []
    refused: list[int] = []
    lock = threading.Lock()

    def _worker() -> None:
        try:
            hold = meter.reserve(request_chars=10)
        except JudgeBudgetExceeded:
            with lock:
                refused.append(1)
            return
        meter.settle(hold, input_tokens=1, output_tokens=1, cached_tokens=0)
        with lock:
            granted.append(1)

    threads = [threading.Thread(target=_worker) for _ in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(granted) == 20
    assert len(refused) == 30
    assert meter.usage().calls == 20


# --- the gateway over a real socket -----------------------------------------------------------


def _post(url: str, payload: dict, timeout: float = 5.0, headers: dict | None = None):
    request = urllib.request.Request(
        f"{url}/inference",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": "cpk_test",
            "x-job-run-id": "1",
            **(headers or {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_the_gateway_forwards_a_call_and_meters_its_real_usage() -> None:
    seen: list[dict] = []

    def _opener(request, timeout=None):
        seen.append(
            {
                "url": request.full_url,
                "body": json.loads(request.data.decode("utf-8")),
                "headers": {k.lower(): v for k, v in request.headers.items()},
                "timeout": timeout,
            }
        )
        return _FakeResponse(_usage_body(prompt=120, completion=45, cached=20))

    limits = JudgeBudgetLimits(max_calls=5, per_request_timeout_seconds=12.0)
    with JudgeGateway(upstream_url="http://upstream:8087", limits=limits, opener=_opener) as gw:
        gw.register_scope("1")
        status, body = _post(gw.url, {"model": "m", "messages": []})

    assert status == 200
    assert body["usage"]["prompt_tokens"] == 120
    assert seen[0]["url"] == "http://upstream:8087/inference"
    assert seen[0]["timeout"] == 12.0
    # The validator's key and the phase header must survive the hop, or the real proxy cannot bill
    # or attribute the call.
    assert seen[0]["headers"]["x-inference-api-key"] == "cpk_test"

    usage = gw.usage()
    assert (usage.calls, usage.input_tokens, usage.output_tokens, usage.cached_tokens) == (
        1,
        120,
        45,
        20,
    )
    assert usage.refusals == 0


def test_the_gateway_injects_the_completion_ceiling_into_every_forwarded_call() -> None:
    seen: list[dict] = []

    def _opener(request, timeout=None):
        seen.append(json.loads(request.data.decode("utf-8")))
        return _FakeResponse(_usage_body())

    limits = JudgeBudgetLimits(max_calls=5, max_output_tokens_per_call=256)
    with JudgeGateway(upstream_url="http://upstream", limits=limits, opener=_opener) as gw:
        gw.register_scope("1")
        _post(gw.url, {"model": "m", "messages": []})  # scorer sends no max_tokens at all
        _post(gw.url, {"model": "m", "messages": [], "max_tokens": 99999})
        _post(gw.url, {"model": "m", "messages": [], "max_tokens": 32})

    assert [payload["max_tokens"] for payload in seen] == [256, 256, 32]


def test_the_gateway_refuses_past_the_ceiling_and_records_it() -> None:
    def _opener(request, timeout=None):
        return _FakeResponse(_usage_body())

    limits = JudgeBudgetLimits(max_calls=1)
    with JudgeGateway(upstream_url="http://upstream", limits=limits, opener=_opener) as gw:
        gw.register_scope("1")
        assert _post(gw.url, {"messages": []})[0] == 200
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(gw.url, {"messages": []})
        assert exc.value.code == 429
        usage = gw.usage()

    # The scorer swallows the 429 and moves on, so this count -- not the response -- is the signal
    # the caller must fail the evaluation on.
    assert usage.calls == 1
    assert usage.refusals == 1
    assert "max_calls" in usage.first_refusal_reason


@pytest.mark.parametrize("header", [None, "unknown", "999"])
def test_missing_malformed_or_unregistered_scope_is_challenge_fatal(header: str | None) -> None:
    def _opener(request, timeout=None):  # pragma: no cover - must never be reached
        raise AssertionError("an unattributed request must not be forwarded")

    gateway = JudgeGateway(
        upstream_url="http://upstream",
        limits=JudgeBudgetLimits(max_calls=5),
        opener=_opener,
    )
    gateway.__enter__()
    gateway.register_scope("123")
    headers = {"Content-Type": "application/json"}
    if header is not None:
        headers["x-job-run-id"] = header
    request = urllib.request.Request(
        f"{gateway.url}/inference",
        data=b'{"messages":[]}',
        headers=headers,
        method="POST",
    )
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)
        assert exc.value.code == 403
        assert gateway.usage().calls == 0
        assert gateway.usage(scope="123").refusals == 0
        assert gateway.usage().protocol_errors == 1
        with pytest.raises(JudgeBudgetError, match="attribution protocol failed"):
            gateway.final_usage()
    finally:
        gateway.__exit__(None, None, None)


def test_an_upstream_failure_settles_the_worst_case_rather_than_zero() -> None:
    def _opener(request, timeout=None):
        raise TimeoutError("read timed out")

    limits = JudgeBudgetLimits(max_calls=5, max_output_tokens_per_call=64)
    with JudgeGateway(upstream_url="http://upstream", limits=limits, opener=_opener) as gw:
        gw.register_scope("1")
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(gw.url, {"messages": []})
        assert exc.value.code == 504
        usage = gw.usage()

    assert usage.calls == 1
    assert usage.upstream_errors == 1
    assert usage.output_tokens == 64


def test_usage_is_attributed_per_scorer_job_under_concurrency() -> None:
    meter = JudgeMeter(JudgeBudgetLimits(max_calls=5))
    first = meter.reserve(request_chars=10, scope="job-a")
    second = meter.reserve(request_chars=10, scope="job-b")
    meter.settle(first, input_tokens=3, output_tokens=2, cached_tokens=0)
    meter.settle_worst_case(second)
    meter.record_refusal("only a", scope="job-a")

    assert meter.usage(scope="job-a").calls == 1
    assert meter.usage(scope="job-a").refusals == 1
    assert meter.usage(scope="job-a").upstream_errors == 0
    assert meter.usage(scope="job-b").calls == 1
    assert meter.usage(scope="job-b").refusals == 0
    assert meter.usage(scope="job-b").upstream_errors == 1
    assert meter.usage().calls == 2


def test_final_usage_charges_an_in_flight_request_before_publishing() -> None:
    started = threading.Event()
    release = threading.Event()

    def _opener(request, timeout=None):
        started.set()
        release.wait(timeout=5)
        return _FakeResponse(_usage_body(prompt=3, completion=2, cached=0))

    gateway = JudgeGateway(
        upstream_url="http://upstream",
        limits=JudgeBudgetLimits(max_calls=5, max_output_tokens_per_call=64),
        opener=_opener,
    )
    gateway.__enter__()
    gateway.register_scope("123")
    client = threading.Thread(
        target=lambda: _post(
            gateway.url,
            {"messages": []},
            headers={"x-job-run-id": "123"},
        )
    )
    client.start()
    assert started.wait(timeout=2)

    usage = gateway.final_usage()
    assert usage.calls == 1
    assert usage.upstream_errors == 1
    assert usage.output_tokens == 64
    assert gateway.usage(scope="123").calls == 1

    release.set()
    client.join(timeout=5)
    gateway.__exit__(None, None, None)
    # The late handler's real receipt cannot double-settle the hold.
    assert gateway.usage().calls == 1


def test_oversized_declared_body_is_refused_before_forwarding() -> None:
    def _opener(request, timeout=None):  # pragma: no cover - must never be reached
        raise AssertionError("oversized body must not be forwarded")

    with JudgeGateway(
        upstream_url="http://upstream",
        limits=JudgeBudgetLimits(max_calls=5, max_request_chars=50),
        opener=_opener,
    ) as gateway:
        gateway.register_scope("2")
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(
                gateway.url,
                {"messages": [{"role": "user", "content": "x" * 100}]},
                headers={"x-job-run-id": "2"},
            )
        assert exc.value.code == 413
        assert gateway.usage().calls == 0
        assert gateway.usage(scope="2").refusals == 1


@pytest.mark.parametrize(
    "body",
    [
        b'{"choices": []}',
        b'{"choices": [], "usage": null}',
        b'{"choices": [], "usage": null, "input_tokens": 3, "output_tokens": 2}',
        b'{"choices": [], "usage": {}}',
        b'{"choices": [], "usage": {"prompt_tokens": 1}}',
    ],
)
def test_a_response_without_an_authoritative_usage_receipt_settles_the_worst_case(
    body: bytes,
) -> None:
    def _opener(request, timeout=None):
        return _FakeResponse(body)

    limits = JudgeBudgetLimits(max_calls=5, max_output_tokens_per_call=64)
    with JudgeGateway(upstream_url="http://upstream", limits=limits, opener=_opener) as gw:
        gw.register_scope("1")
        _post(gw.url, {"messages": []})
        usage = gw.usage()

    assert usage.calls == 1
    assert usage.output_tokens == 64
    # The point of every one of these bodies: a partial or absent receipt must NEVER be read as
    # cheap. The proxy's flattened ``input_tokens``/``output_tokens`` default to zero, so the third
    # case in particular would undercount real spend if they were trusted.
    assert usage.unmetered_calls == 1
    # Not an upstream failure: the call was answered, so the score it produced is complete.
    assert usage.upstream_errors == 0


def test_the_gateway_is_not_a_general_proxy() -> None:
    def _opener(request, timeout=None):  # pragma: no cover - must never be reached
        raise AssertionError("nothing may be forwarded for an unknown endpoint")

    with JudgeGateway(
        upstream_url="http://upstream", limits=JudgeBudgetLimits(max_calls=5), opener=_opener
    ) as gw:
        request = urllib.request.Request(f"{gw.url}/metrics/job-runs/1/summary/reset", data=b"{}")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)
        assert exc.value.code == 404


def test_a_malformed_payload_is_rejected_without_spending() -> None:
    def _opener(request, timeout=None):  # pragma: no cover - must never be reached
        raise AssertionError("a malformed payload must not be forwarded")

    with JudgeGateway(
        upstream_url="http://upstream", limits=JudgeBudgetLimits(max_calls=5), opener=_opener
    ) as gw:
        gw.register_scope("1")
        request = urllib.request.Request(
            f"{gw.url}/inference",
            data=b"not json",
            headers={"Content-Type": "application/json", "x-job-run-id": "1"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=5)
        assert exc.value.code == 400
        assert gw.usage().calls == 0
        assert gw.usage().protocol_errors == 1


def test_the_url_is_loopback_only() -> None:
    """Validator-paid capacity must not be reachable from the miner containers, which have their
    own INFERENCE_API and pay with their own key."""
    with JudgeGateway(
        upstream_url="http://upstream", limits=JudgeBudgetLimits(max_calls=1)
    ) as gw:
        assert gw.url.startswith("http://127.0.0.1:")


# --- the lane's configuration surface ---------------------------------------------------------


def test_an_unconfigured_lane_is_unmetered() -> None:
    """None means the pre-existing behaviour, so the gateway can land without forcing every
    deployment to pick numbers the same day."""
    from kata_sn60.execution.judge_gateway import judge_limits_from_env

    assert judge_limits_from_env({}) is None


def test_the_caps_are_read_from_the_lane_env() -> None:
    from kata_sn60.execution.judge_gateway import judge_limits_from_env

    limits = judge_limits_from_env(
        {
            "KATA_SN60_JUDGE_MAX_CALLS": "800",
            "KATA_SN60_JUDGE_MAX_TOKS": "4000000",
            "KATA_SN60_JUDGE_MAX_SPEND_USD": "12.5",
            "KATA_SN60_JUDGE_USD_PER_MTOK_INPUT": "0.2",
            "KATA_SN60_JUDGE_USD_PER_MTOK_OUTPUT": "0.8",
            "KATA_SN60_JUDGE_REQUEST_TIMEOUT_SECONDS": "90",
            "KATA_SN60_JUDGE_DEADLINE_SECONDS": "5400",
            "KATA_SN60_JUDGE_MAX_OUTPUT_TOKS": "2048",
        }
    )
    assert limits is not None
    assert limits.max_calls == 800
    assert limits.max_total_tokens == 4_000_000
    assert limits.max_spend_usd == 12.5
    assert limits.per_request_timeout_seconds == 90.0
    assert limits.challenge_deadline_seconds == 5400.0
    assert limits.max_output_tokens_per_call == 2048


def test_a_cap_without_a_call_ceiling_is_a_configuration_error() -> None:
    """Every other bound is a multiple of the call count, so a spend cap on its own bounds
    nothing."""
    from kata_sn60.execution.judge_gateway import judge_limits_from_env

    with pytest.raises(JudgeBudgetError, match="needs a call ceiling"):
        judge_limits_from_env({"KATA_SN60_JUDGE_MAX_TOKS": "1000"})


def test_a_non_numeric_cap_fails_closed() -> None:
    from kata_sn60.execution.judge_gateway import judge_limits_from_env

    with pytest.raises(JudgeBudgetError, match="is not a number"):
        judge_limits_from_env(
            {"KATA_SN60_JUDGE_MAX_CALLS": "800", "KATA_SN60_JUDGE_MAX_TOKS": "lots"}
        )


def test_every_limits_field_has_an_env_var() -> None:
    """A field missing from the table is a cap no operator can set."""
    import dataclasses

    from kata_sn60.execution.judge_gateway import JUDGE_ENV

    assert {f.name for f in dataclasses.fields(JudgeBudgetLimits)} == set(JUDGE_ENV)


def test_every_judge_env_var_is_deployable() -> None:
    """The installer refuses any lane env key containing a credential-ish substring
    (``unit_render._LANE_ENV_DENY_SUBSTRINGS``), so a cap named ``..._MAX_TOKENS`` would be
    silently dropped and the gateway would never turn on in production. These are numeric ceilings,
    not credentials, so they are named to clear that guard rather than the guard weakened."""
    from kata_sn60.execution.judge_gateway import JUDGE_ENV

    denied = ("TOKEN", "SECRET", "WEBHOOK", "PASSWORD", "KEY")
    for var in JUDGE_ENV.values():
        assert var.startswith("KATA_SN60_"), var  # the installer's per-subnet prefix rule
        assert not any(bad in var for bad in denied), var


# --- an answered call with no usage receipt ------------------------------------------------------
#
# Charging it at the reservation is NOT negotiable: the proxy's flattened token fields default to
# zero, so reading them would let a missing receipt look like "spent nothing". What these pin is
# that being blind to the COST does not also mean discarding a complete SCORE.


def test_a_missing_usage_receipt_is_charged_at_the_reservation() -> None:
    def _opener(request, timeout=None):
        return _FakeResponse(json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode())

    limits = JudgeBudgetLimits(max_calls=5, max_output_tokens_per_call=64)
    with JudgeGateway(upstream_url="http://up", limits=limits, opener=_opener) as gw:
        gw.register_scope("12345")
        assert _post(gw.url, {"messages": []}, headers={"x-job-run-id": "12345"})[0] == 200
        usage = gw.usage()

    # Conservative on money: the full reservation, never the zero-default flattened fields.
    assert usage.calls == 1
    assert usage.output_tokens == 64
    assert usage.input_tokens > 0
    assert usage.unmetered_calls == 1
    # Precise about completeness: the judge answered, so this is not an upstream failure.
    assert usage.upstream_errors == 0


def test_a_real_upstream_failure_is_still_an_upstream_error() -> None:
    """The distinction only holds if the genuine failure keeps failing."""
    def _opener(request, timeout=None):
        raise TimeoutError("read timed out")

    limits = JudgeBudgetLimits(max_calls=5, max_output_tokens_per_call=64)
    with JudgeGateway(upstream_url="http://up", limits=limits, opener=_opener) as gw:
        gw.register_scope("12345")
        with pytest.raises(urllib.error.HTTPError):
            _post(gw.url, {"messages": []}, headers={"x-job-run-id": "12345"})
        usage = gw.usage()

    assert usage.upstream_errors == 1
    assert usage.unmetered_calls == 0
    assert usage.output_tokens == 64  # charged identically


def test_holds_still_in_flight_at_shutdown_are_upstream_errors() -> None:
    """An abandoned call never answered, so it is indeterminate rather than merely unmetered."""
    limits = JudgeBudgetLimits(max_calls=5, max_output_tokens_per_call=64)
    meter = JudgeMeter(limits)
    meter.reserve(request_chars=100, scope="12345")
    meter.settle_all_holds_worst_case()
    usage = meter.usage()
    assert usage.upstream_errors == 1
    assert usage.unmetered_calls == 0
