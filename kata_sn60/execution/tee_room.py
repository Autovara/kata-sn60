"""Sealed-room (TEE) execution for SN60 -- the Kata side.

A candidate can be run inside a confidential VM (Phala/dstack) that the miner pays for and
whose key the owner never sees. This module holds the Kata-side pieces:

  * verify_room_run  -- check the room's attestation (genuine TEE, approved image, binds
                        this exact answer + round), before trusting the answer;
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
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

# Shared HMAC secret the room requires on /run (room.auth). Must match the room's
# KATA_ROOM_AUTH_SECRET so only this validator can invoke a run.
ROOM_AUTH_SECRET_ENV = "KATA_ROOM_AUTH_SECRET"
ROOM_SIGNATURE_HEADER = "X-Kata-Signature"


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

    `parse_quote()` gives report_data + the TD measurement registers; `verify()` checks the
    signature/TCB against Intel/Phala PCCS collateral. The runner image is identified by
    RTMR3 (the app/compose measurement; MRTD/RTMR0-2 are firmware/OS shared by all dstack
    apps), overridable via KATA_SN60_ROOM_MEASUREMENT_REGISTER.

    CONFIRM on real hardware (A6 step 0): the exact collateral-fetch call, the attribute
    names (`report_data`, `rt_mr3`), and which TCB statuses to accept. Those are the only
    unknowns; the surrounding logic is tested.
    """

    ACCEPT_STATUS = frozenset(
        {"UpToDate", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded"}
    )

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
            report = parsed.report
            report_data = report.report_data
            # Approved-image identity = the dstack COMPOSE-HASH (stable across redeploys),
            # encoded in mr_config_id (byte 0 = version tag, bytes 1..33 = compose-hash).
            # rt_mr3 is NOT usable: it folds in per-instance app-id/instance-id, so it
            # changes on every deployment. Override via KATA_SN60_ROOM_MEASUREMENT_REGISTER.
            register = _os.environ.get("KATA_SN60_ROOM_MEASUREMENT_REGISTER", "compose_hash")
            if register == "compose_hash":
                measurement = report.mr_config_id[1:33].hex()
            else:
                measurement = getattr(report, register).hex()
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
            status = getattr(verified, "status", "")
            if status not in self.ACCEPT_STATUS:
                return VerifiedQuote(False, report_data, measurement, f"tcb status {status}")
            return VerifiedQuote(True, report_data, measurement, "ok")
        except Exception as exc:  # noqa: BLE001
            return VerifiedQuote(False, b"", "", f"dcap-qvl error: {exc}")


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


def evaluate_candidate_in_room(
    *,
    candidate_id: str,
    agent_ref: str,
    project_key: str,
    sealed_key_ref: str,
    nonce: bytes,
    bundle_sha256: str,
    policy: RoomPolicy,
    launcher: RoomLauncher,
    verifier: QuoteVerifier,
    seen_nonces: set | None = None,
) -> CandidateOutcome:
    try:
        result = launcher.launch_and_run(
            candidate_id=candidate_id,
            agent_ref=agent_ref,
            project_key=project_key,
            nonce=nonce,
            sealed_key_ref=sealed_key_ref,
            bundle_sha256=bundle_sha256,
        )
    except Exception as exc:  # noqa: BLE001 - a room failure is a failed run, not a crash
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
    return CandidateOutcome(True, result.report, "ok")


def _bundle_tar_b64(bundle_root: str) -> str:
    """Tar+gzip+base64 the candidate's submission bundle so the room can run the real
    agent. Excludes caches/VCS noise; the room extracts it to /kata_bundle."""
    import base64
    import io
    import tarfile

    def _keep(ti: "tarfile.TarInfo"):
        n = ti.name
        if "__pycache__" in n or n.endswith(".pyc") or "/.git" in n or n == "./.git":
            return None
        return ti

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(bundle_root, arcname=".", filter=_keep)
    return base64.b64encode(buf.getvalue()).decode()


class HttpRoomLauncher:
    """Drive ONE running room over HTTP, per candidate (sealed key travels per request)."""

    def __init__(self, base_url: str, timeout: float = 900.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

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
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")[:400]
            raise RuntimeError(f"room HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"could not reach room: {exc.reason}") from exc
        if (
            "report" not in data
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
