"""Sealed-room (TEE) execution for SN60 -- the Kata side.

A candidate can be run inside a confidential VM (Phala/dstack) that the miner pays for and
whose key the owner never sees. This module holds the Kata-side pieces:

  * verify_room_run  -- check the room's attestation (genuine TEE, approved image, binds
                        this exact answer + challenge), before trusting the answer;
  * evaluate_candidate_in_room -- mint a nonce, run the candidate in the room, verify, and
                        return the verified answer (report) for the normal judge to score;
  * HttpRoomLauncher -- drive ONE running room over HTTP, per candidate (the miner's sealed
                        key travels per request; the room decrypts it inside).

Kata never sees the miner's key and never runs the raw inference itself. Decryption happens
inside the room, so this module needs no crypto -- only stdlib. The raw quote signature
check is delegated to a QuoteVerifier (default: the dcap-qvl CLI), so the logic is testable
with a fake verifier.

The generic runner handles the sealed network and miner-funded inference gateway;
this module is only the SN60 validator-side room protocol and attestation check.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

# A room run is retried only on transient TRANSPORT failures: a connection reset/
# refused/dropped ("Remote end closed connection"), a socket timeout, or a
# 502/503/504 from the fronting gateway. Anything else (a 4xx, a room error
# payload, a failed attestation) is a real rejection and must not be retried.
_RETRYABLE_ROOM_HTTP_STATUS = frozenset({502, 503, 504})
ROOM_MAX_ATTEMPTS_ENV = "KATA_SN60_ROOM_MAX_ATTEMPTS"
ROOM_RETRY_BASE_SECONDS_ENV = "KATA_SN60_ROOM_RETRY_BASE_SECONDS"


class RoomTransportError(RuntimeError):
    """A transient transport failure reaching the room.

    Distinct from a verified rejection or an agent fault so the caller can retry
    it -- with a freshly minted nonce, because the room's single-use replay guard
    rejects a reused nonce.
    """


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _open_room(request, *, timeout: float):
    return urllib.request.build_opener(_RejectRedirects).open(request, timeout=timeout)


# Shared HMAC secret the room requires on /run (room.auth). Must match the room's
# KATA_ROOM_AUTH_SECRET so only this validator can invoke a run.
ROOM_AUTH_SECRET_ENV = "KATA_ROOM_AUTH_SECRET"
ROOM_SIGNATURE_HEADER = "X-Kata-Signature"
ROOM_HTTP_TIMEOUT_ENV = "KATA_SN60_ROOM_HTTP_TIMEOUT_SECONDS"
DEFAULT_ROOM_HTTP_TIMEOUT_SECONDS = 900.0
MAX_ROOM_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 256 * 1024
MAX_BUNDLE_FILES = 16
SEALED_CREDENTIAL_FILENAME = "sealed_inference_key"
_BUNDLE_BINDING_DOMAIN = b"kata-miner-credential-bundle-v1\0"


def room_signature(body: bytes) -> str:
    """HMAC-SHA256 hex of the exact /run request body, keyed by the shared room secret."""
    secret = os.environ.get(ROOM_AUTH_SECRET_ENV, "").strip().encode()
    if not secret:
        raise RuntimeError(
            f"{ROOM_AUTH_SECRET_ENV} is not set; cannot authenticate to the sealed room."
        )
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def canonical(obj) -> bytes:
    """Stable byte form of the answer so its hash matches on both sides."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def binding_payload(*, report: object, bundle_sha256: str, provenance: dict[str, object]) -> dict:
    """Must remain byte-for-byte equivalent to ``room.attest.binding_payload``."""
    return {
        "report": report,
        "bundle_sha256": bundle_sha256,
        "provenance": provenance,
    }


# -- attestation verification ------------------------------------------------


@dataclass(frozen=True)
class VerifiedQuote:
    ok: bool
    report_data: bytes
    measurement: str
    detail: str = ""


class QuoteVerifier(Protocol):
    def verify(self, quote_hex: str) -> VerifiedQuote: ...


@dataclass(frozen=True)
class RoomPolicy:
    approved_measurements: frozenset[str]


@dataclass(frozen=True)
class AttestationResult:
    accepted: bool
    reason: str


def verify_room_run(
    *,
    quote_hex: str,
    report: object,
    nonce: bytes,
    project_key: str,
    bundle_sha256: str,
    provenance: dict[str, object],
    policy: RoomPolicy,
    verifier: QuoteVerifier,
    seen_nonces: set | None = None,
) -> AttestationResult:
    vq = verifier.verify(quote_hex)
    if not vq.ok:
        return AttestationResult(False, f"quote not verified: {vq.detail}")
    if vq.measurement not in policy.approved_measurements:
        return AttestationResult(False, f"runner image not approved: {vq.measurement}")
    binding_hash = hashlib.sha256(
        canonical(
            binding_payload(
                report=report,
                bundle_sha256=bundle_sha256,
                provenance=provenance,
            )
        )
    ).digest()
    expected = hashlib.sha256(nonce + project_key.encode() + binding_hash).digest()
    if vq.report_data[:32] != expected:
        return AttestationResult(False, "quote does not cover this answer (swap or replay)")
    if seen_nonces is not None:
        if nonce in seen_nonces:
            return AttestationResult(False, "nonce already used (replay)")
        seen_nonces.add(nonce)
    return AttestationResult(True, "ok")


class DcapQvlVerifier:
    """Verify a TDX quote with the dcap-qvl Python package.

    dcap-qvl 0.5.x exposes TDX fields through ``parse_quote().report`` and verifies the signature,
    certificate chain, revocation state and TCB against PCCS collateral. The stable dstack image
    identity is the compose hash stored in ``mr_config_id[1:33]``; per-instance RTMR values are not
    suitable allowlist identities.
    """

    ACCEPT_STATUS = frozenset({"OK", "SW_HARDENING_NEEDED"})
    STATUS_ALIASES = {
        "UpToDate": "OK",
        "SWHardeningNeeded": "SW_HARDENING_NEEDED",
    }

    def verify(self, quote_hex: str) -> VerifiedQuote:
        try:
            import time as _time

            import dcap_qvl
        except ImportError:
            return VerifiedQuote(False, b"", "", "dcap-qvl python package not installed")
        try:
            import os as _os

            raw = bytes.fromhex(quote_hex)
            parsed = dcap_qvl.parse_quote(raw)
            if hasattr(parsed, "is_tdx") and not parsed.is_tdx():
                return VerifiedQuote(False, b"", "", "quote is not TDX")
            report = parsed.report
            report_data = bytes(report.report_data)
            # Approved-image identity = the dstack COMPOSE-HASH (stable across redeploys),
            # encoded in mr_config_id (byte 0 = version tag, bytes 1..33 = compose-hash).
            # rt_mr3 is NOT usable: it folds in per-instance app-id/instance-id, so it
            # changes on every deployment. Override via KATA_SN60_ROOM_MEASUREMENT_REGISTER.
            register = _os.environ.get("KATA_SN60_ROOM_MEASUREMENT_REGISTER", "compose_hash")
            if register == "compose_hash":
                mr_config_id = bytes(report.mr_config_id)
                if len(mr_config_id) < 33:
                    return VerifiedQuote(False, report_data, "", "mr_config_id is incomplete")
                measurement = mr_config_id[1:33].hex()
            else:
                measurement = bytes(getattr(report, register)).hex()
            import asyncio as _asyncio
            import inspect as _inspect

            pccs = _os.environ.get("KATA_SN60_PCCS_URL", dcap_qvl.PHALA_PCCS_URL)

            async def _collateral_and_verify():
                col = dcap_qvl.get_collateral(pccs, raw)
                if _inspect.isawaitable(col):
                    col = await col
                v = dcap_qvl.verify(raw, col, int(_time.time()))
                if _inspect.isawaitable(v):
                    v = await v
                return v

            verified = _asyncio.run(_collateral_and_verify())
            raw_status = str(getattr(verified, "status", ""))
            status = self.STATUS_ALIASES.get(raw_status, raw_status)
            if status not in self.ACCEPT_STATUS:
                return VerifiedQuote(False, report_data, measurement, f"tcb status {raw_status}")
            return VerifiedQuote(True, report_data, measurement, "ok")
        except Exception as exc:  # noqa: BLE001
            return VerifiedQuote(False, b"", "", f"dcap-qvl error: {exc}")


def verify_room_identity(
    base_url: str,
    *,
    policy: RoomPolicy,
    verifier: QuoteVerifier,
    timeout: float = 15.0,
) -> None:
    """Check room health and prove that its published sealing key is quote-bound."""
    base = base_url.rstrip("/")
    try:
        with _open_room(f"{base}/health", timeout=timeout) as response:
            health = json.loads(response.read().decode())
        if not isinstance(health, dict) or health.get("ok") is not True:
            raise RuntimeError("room /health did not report ok")
        with _open_room(f"{base}/pubkey", timeout=timeout) as response:
            document = json.loads(response.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"cannot reach the SN60 room health endpoints: {exc}") from exc
    if not isinstance(document, dict):
        raise RuntimeError("room /pubkey returned a non-object response")
    public_key = document.get("pubkey")
    quote_hex = document.get("quote")
    if (
        not isinstance(public_key, str)
        or len(public_key) != 66
        or not all(char in "0123456789abcdef" for char in public_key)
        or not isinstance(quote_hex, str)
    ):
        raise RuntimeError("room /pubkey returned an invalid key or quote")
    quote = verifier.verify(quote_hex)
    if not quote.ok:
        raise RuntimeError(f"room /pubkey quote was not verified: {quote.detail}")
    if quote.measurement not in policy.approved_measurements:
        raise RuntimeError(f"room /pubkey measurement is not approved: {quote.measurement}")
    expected = hashlib.sha256(b"kata-sealing-pubkey:" + bytes.fromhex(public_key)).digest()
    if not hmac.compare_digest(quote.report_data[:32], expected):
        raise RuntimeError("room /pubkey quote does not bind the published sealing key")


# -- run a candidate in a room -----------------------------------------------


@dataclass(frozen=True)
class RoomResult:
    report: object
    quote_hex: str
    bundle_sha256: str
    provenance: dict[str, object]


class RoomLauncher(Protocol):
    def launch_and_run(
        self,
        *,
        candidate_id: str,
        agent_ref: str,
        project_key: str,
        nonce: bytes,
        sealed_key_ref: str,
        bundle_sha256: str,
    ) -> RoomResult: ...


@dataclass(frozen=True)
class CandidateOutcome:
    accepted: bool
    report: object | None
    reason: str
    # Trusted room provenance (attested), incl. the per-run ``inference_summary`` (e.g. all-402 =>
    # the miner's provider key is out of credits). ``None`` when the run did not reach the room.
    provenance: dict | None = None


def evaluate_candidate_in_room(
    *,
    candidate_id: str,
    agent_ref: str,
    project_key: str,
    sealed_key_ref: str,
    mint_nonce: Callable[[], bytes],
    bundle_sha256: str,
    policy: RoomPolicy,
    launcher: RoomLauncher,
    verifier: QuoteVerifier,
    seen_nonces: set | None = None,
    max_attempts: int | None = None,
) -> CandidateOutcome:
    """Run one candidate in the room, retrying only transient transport failures.

    A dropped connection / socket timeout / 502-504 (``RoomTransportError``) is
    retried with a FRESH nonce -- the room's single-use replay guard would 409 a
    reused one. A verified rejection, a bad bundle hash, or any other room failure
    is returned immediately (no retry): each is a real, non-transient fault.
    """
    attempts = resolve_room_max_attempts() if max_attempts is None else max(1, max_attempts)
    transport_reason = "room run failed"
    for attempt in range(1, attempts + 1):
        nonce = mint_nonce()
        try:
            result = launcher.launch_and_run(
                candidate_id=candidate_id,
                agent_ref=agent_ref,
                project_key=project_key,
                nonce=nonce,
                sealed_key_ref=sealed_key_ref,
                bundle_sha256=bundle_sha256,
            )
        except RoomTransportError as exc:
            transport_reason = str(exc)
            if attempt < attempts:
                time.sleep(_room_retry_backoff_seconds(attempt))
                continue
            return CandidateOutcome(
                False, None, f"room unreachable after {attempts} attempt(s): {transport_reason}"
            )
        except Exception as exc:  # noqa: BLE001 - a non-transport room failure is not retryable
            return CandidateOutcome(False, None, f"room run failed: {exc}")

        if result.bundle_sha256 != bundle_sha256:
            return CandidateOutcome(False, None, "room returned a different candidate bundle hash")

        verdict = verify_room_run(
            quote_hex=result.quote_hex,
            report=result.report,
            nonce=nonce,
            project_key=project_key,
            bundle_sha256=bundle_sha256,
            provenance=result.provenance,
            policy=policy,
            verifier=verifier,
            seen_nonces=seen_nonces,
        )
        if not verdict.accepted:
            return CandidateOutcome(False, None, verdict.reason)
        return CandidateOutcome(
            True,
            result.report,
            "ok",
            provenance=result.provenance if isinstance(result.provenance, dict) else None,
        )

    return CandidateOutcome(False, None, transport_reason)


def _bundle_files(root: Path) -> list[Path]:
    if not root.is_dir():
        raise RuntimeError(f"candidate bundle does not exist: {root}")
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in {".git", "__pycache__"} for part in relative.parts):
            continue
        if path.is_symlink():
            raise RuntimeError(f"candidate bundle contains a symlink: {relative}")
        if path.is_file() and path.suffix not in {".pyc", ".pyo"}:
            files.append(path)
            if len(files) > MAX_BUNDLE_FILES:
                raise RuntimeError(
                    f"candidate bundle exceeds the {MAX_BUNDLE_FILES}-file room policy"
                )
    if sum(path.stat().st_size for path in files) > MAX_BUNDLE_BYTES:
        raise RuntimeError(
            f"candidate bundle exceeds the {MAX_BUNDLE_BYTES}-byte room policy"
        )
    return files


def hash_room_bundle(bundle_root: str | Path) -> str:
    """Hash the executable bundle using the room's credential-binding format."""
    root = Path(bundle_root).expanduser().resolve()
    files = _bundle_files(root)
    if not files:
        raise RuntimeError("candidate bundle is empty")
    digest = hashlib.sha256(_BUNDLE_BINDING_DOMAIN)
    for path in files:
        relative = path.relative_to(root).as_posix()
        if relative == SEALED_CREDENTIAL_FILENAME:
            continue
        encoded_path = relative.encode()
        content = path.read_bytes()
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _bundle_tar_b64(bundle_root: str) -> str:
    """Tar+gzip+base64 the bounded candidate bundle for execution in the room."""
    import base64
    import io
    import tarfile

    root = Path(bundle_root).expanduser().resolve()
    files = _bundle_files(root)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path in files:
            tf.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
    return base64.b64encode(buf.getvalue()).decode()


class HttpRoomLauncher:
    """Drive ONE running room over HTTP, per candidate (sealed key travels per request)."""

    def __init__(self, base_url: str, timeout: float | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = resolve_room_http_timeout_seconds() if timeout is None else timeout

    def launch_and_run(
        self,
        *,
        candidate_id: str,
        agent_ref: str,
        project_key: str,
        nonce: bytes,
        sealed_key_ref: str,
        bundle_sha256: str,
    ) -> RoomResult:
        issued_at = int(time.time())
        lifetime = int(os.environ.get("KATA_SN60_ROOM_REQUEST_LIFETIME_SECONDS", "900"))
        if not 1 <= lifetime <= 1_200:
            raise RuntimeError("KATA_SN60_ROOM_REQUEST_LIFETIME_SECONDS must be 1..1200")
        payload = json.dumps(
            {
                "nonce": nonce.hex(),
                "project_key": project_key,
                "sealed_key": sealed_key_ref,
                "bundle": _bundle_tar_b64(agent_ref),  # the miner's real agent, run in the room
                "bundle_sha256": bundle_sha256,
                "issued_at": issued_at,
                "expires_at": issued_at + lifetime,
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.base_url}/run",
            data=payload,
            headers={
                "Content-Type": "application/json",
                ROOM_SIGNATURE_HEADER: room_signature(payload),
            },
            method="POST",
        )
        try:
            with _open_room(req, timeout=self.timeout) as resp:
                raw_response = resp.read(MAX_ROOM_RESPONSE_BYTES + 1)
            if len(raw_response) > MAX_ROOM_RESPONSE_BYTES:
                raise RuntimeError("room response exceeds the 4 MiB safety limit")
            data = json.loads(raw_response.decode())
        except urllib.error.HTTPError as exc:
            body = exc.read(401).decode(errors="replace")[:400]
            # 502/503/504 are transient gateway/proxy failures -> retryable.
            if exc.code in _RETRYABLE_ROOM_HTTP_STATUS:
                raise RoomTransportError(f"room HTTP {exc.code}: {body}") from exc
            raise RuntimeError(f"room HTTP {exc.code}: {body}") from exc
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            ConnectionError,
            TimeoutError,
        ) as exc:
            # Connection reset/refused/dropped or a socket timeout: the room may
            # never have run, so a fresh-nonce retry is safe.
            reason = getattr(exc, "reason", exc)
            raise RoomTransportError(f"could not reach room: {reason}") from exc
        if (
            not isinstance(data, dict)
            or "report" not in data
            or "quote" not in data
            or data.get("bundle_sha256") != bundle_sha256
            or not isinstance(data.get("provenance"), dict)
        ):
            raise RuntimeError(f"room error: {data.get('error', data)}")
        return RoomResult(
            report=data["report"],
            quote_hex=data["quote"],
            bundle_sha256=data["bundle_sha256"],
            provenance=data["provenance"],
        )


def resolve_room_max_attempts() -> int:
    """How many times to attempt one room run before giving up (1..5, default 3)."""

    raw = os.environ.get(ROOM_MAX_ATTEMPTS_ENV, "3").strip()
    try:
        value = int(raw)
    except ValueError:
        return 3
    return value if 1 <= value <= 5 else 3


def _room_retry_backoff_seconds(attempt: int) -> float:
    """Exponential backoff with jitter before retrying a transient room failure."""

    try:
        base = float(os.environ.get(ROOM_RETRY_BASE_SECONDS_ENV, "2") or "2")
    except ValueError:
        base = 2.0
    delay = min(15.0, max(0.0, base) * (2 ** (attempt - 1)))
    return delay + random.uniform(0.0, delay * 0.25)


def resolve_room_http_timeout_seconds() -> float:
    """Return the validator-side HTTP deadline for one sealed-room request."""

    raw = os.environ.get(ROOM_HTTP_TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_ROOM_HTTP_TIMEOUT_SECONDS
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{ROOM_HTTP_TIMEOUT_ENV} must be a positive number") from exc
    if timeout <= 0:
        raise RuntimeError(f"{ROOM_HTTP_TIMEOUT_ENV} must be a positive number")
    return timeout
