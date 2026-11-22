"""Verifier (Università di Salerno): verifies presentations (WP2, phase 3, step 7)."""

from __future__ import annotations

import datetime as dt
import json
import logging
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from credential_sharing.actors.institution import Institution
from credential_sharing.auth import Clock
from credential_sharing.credential import PRESENTATION_TYPES, claim_leaf_hash, verify_document
from credential_sharing.crypto.merkle import verify_proof
from credential_sharing.crypto.secure_channel import SealedMessage, open_sealed
from credential_sharing.encoding import b64url_decode, utc_now
from credential_sharing.errors import ChannelError, DIDResolutionError, VerificationError
from credential_sharing.identity.did import public_key_from_did_document
from credential_sharing.verification import (
    TrustContext,
    check_credential_shape,
    check_status,
    check_validity_period,
    require_accredited,
    verify_issuer_signature,
)

log = logging.getLogger(__name__)

REQUEST_TTL_SECONDS = 5 * 60
_MALFORMED = (KeyError, TypeError, ValueError, AttributeError, IndexError)


@dataclass(frozen=True)
class StepResult:
    step: str
    title: str
    passed: bool
    detail: str


@dataclass
class VerificationReport:
    steps: list[StepResult] = field(default_factory=list)
    valid: bool = False
    holder: str | None = None
    issuer: str | None = None
    accepted_claims: dict[str, Any] = field(default_factory=dict)
    ignored_claims: list[str] = field(default_factory=list)

    @property
    def failure(self) -> StepResult | None:
        return next((step for step in self.steps if not step.passed), None)


@dataclass
class _PendingRequest:
    request: dict[str, Any]
    expires_at: float


Check = Callable[[dict[str, Any], dict[str, Any], dt.datetime], str]


class Verifier(Institution):
    role = "Verifier"
    service_type = "PresentationRequestService"

    def __init__(self, name: str, *, trust: TrustContext, clock: Clock = time.monotonic) -> None:
        super().__init__(name)
        self._trust = trust
        self._clock = clock
        self._pending: dict[str, _PendingRequest] = {}

    def create_presentation_request(self, requested_claims: Iterable[str] = ()) -> dict[str, Any]:
        """Start of the challenge-response: a fresh nonce bound to this verifier."""
        request = {
            "type": "PresentationRequest",
            "challenge": secrets.token_urlsafe(32),
            "domain": self.did,
            "requestedClaims": list(requested_claims),
        }
        self._pending[request["challenge"]] = _PendingRequest(request, self._clock() + REQUEST_TTL_SECONDS)
        return dict(request)

    def receive_presentation(
        self, message: SealedMessage, *, now: dt.datetime | None = None
    ) -> VerificationReport:
        channel_step = ("TLS", "Secure channel (AES-256-GCM)")
        try:
            presentation = json.loads(open_sealed(message, recipient=self.did, recipient_keys=self._keys))
        except (ChannelError, ValueError) as exc:
            log.warning("%s: [FAIL] %s - %s", self.name, channel_step[1], exc)
            return VerificationReport(steps=[StepResult(*channel_step, False, str(exc))])
        report = self.verify_presentation(presentation, now=now)
        report.steps.insert(0, StepResult(*channel_step, True, "payload decrypted and authenticated"))
        return report

    def verify_presentation(
        self, presentation: dict[str, Any], *, now: dt.datetime | None = None
    ) -> VerificationReport:
        now = now or utc_now()
        report = VerificationReport()
        state: dict[str, Any] = {}
        checks: list[tuple[str, str, Check]] = [
            ("7.A", "Holder signature and holder binding", self._check_holder),
            ("7.B", "Issuer signature and Merkle proofs", self._check_disclosures),
            ("7.C", "Issuer DID, role and accreditation", self._check_issuer_accreditation),
            ("7.D", "Revocation status and validity period", self._check_status),
            ("7.E", "Challenge-response (freshness and audience)", self._check_challenge),
            ("7.F", "Selective processing of requested claims", self._check_requested_claims),
        ]
        for code, title, check in checks:
            try:
                detail = check(presentation, state, now)
            except (VerificationError, DIDResolutionError) as exc:
                return self._fail(report, code, title, str(exc))
            except _MALFORMED as exc:
                return self._fail(report, code, title, f"malformed presentation ({type(exc).__name__}: {exc})")
            report.steps.append(StepResult(code, title, True, detail))
            log.info("%s: [ OK ] %s %s - %s", self.name, code, title, detail)

        report.valid = True
        report.holder = state["holder"]
        report.issuer = state["issuer"]
        report.accepted_claims = state["accepted"]
        report.ignored_claims = state["ignored"]
        log.info("%s: presentation ACCEPTED", self.name)
        return report

    def _fail(self, report: VerificationReport, code: str, title: str, detail: str) -> VerificationReport:
        report.steps.append(StepResult(code, title, False, detail))
        log.warning("%s: [FAIL] %s %s - %s", self.name, code, title, detail)
        log.warning("%s: presentation REJECTED", self.name)
        return report

    # -- the six verification steps of WP2 ---------------------------------

    def _check_holder(self, vp: dict[str, Any], state: dict[str, Any], now: dt.datetime) -> str:
        if vp["type"] != PRESENTATION_TYPES:
            raise VerificationError("not a VerifiablePresentation")
        holder = vp["holder"]
        credentials = vp["verifiableCredential"]
        if not isinstance(credentials, list) or len(credentials) != 1:
            raise VerificationError("exactly one credential per presentation is supported")
        proof = vp["proof"]
        if not proof["verificationMethod"].startswith(holder + "#") or proof["proofPurpose"] != "authentication":
            raise VerificationError("presentation proof is not an authentication proof by the holder")
        holder_key = public_key_from_did_document(
            self._trust.resolver.resolve_student(holder), proof["verificationMethod"]
        )
        if not verify_document(vp, holder_key):
            raise VerificationError("holder signature on the presentation is invalid")
        credential = credentials[0]
        if credential["credentialSubject"]["id"] != holder:
            raise VerificationError("the presenter is not the subject of the credential")
        state.update(holder=holder, credential=credential)
        return f"signed by {holder}, who is the credential subject"

    def _check_disclosures(self, vp: dict[str, Any], state: dict[str, Any], now: dt.datetime) -> str:
        credential = state["credential"]
        check_credential_shape(credential)
        issuer = credential["issuer"]["id"]
        verify_issuer_signature(credential, self._trust.resolver.resolve_institution(issuer))
        root = b64url_decode(credential["proof"]["merkleRoot"])
        disclosed: dict[str, Any] = {}
        for item in credential["disclosedClaims"]:
            name = item["name"]
            if name in disclosed:
                raise VerificationError(f"claim {name!r} disclosed twice")
            leaf = claim_leaf_hash(name, item["salt"], item["value"])
            if not verify_proof(leaf, item["proof"], root):
                raise VerificationError(f"Merkle proof of claim {name!r} does not match the signed root")
            disclosed[name] = item["value"]
        if not disclosed:
            raise VerificationError("the presentation discloses no claim")
        state.update(issuer=issuer, disclosed=disclosed)
        return f"issuer signature valid, {len(disclosed)} claim(s) proven against the Merkle root"

    def _check_issuer_accreditation(self, vp: dict[str, Any], state: dict[str, Any], now: dt.datetime) -> str:
        require_accredited(self._trust, state["issuer"], "Issuer", now=now)
        return "accredited Issuer, X.509 certificate chains to the AE root"

    def _check_status(self, vp: dict[str, Any], state: dict[str, Any], now: dt.datetime) -> str:
        check_status(self._trust, state["credential"])
        check_validity_period(state["credential"], now)
        return "credential is Valid on the ledger and not expired"

    def _check_challenge(self, vp: dict[str, Any], state: dict[str, Any], now: dt.datetime) -> str:
        proof = vp["proof"]
        if proof.get("domain") != self.did:
            raise VerificationError("presentation was created for another verifier")
        pending = self._pending.pop(proof.get("challenge"), None)  # single use
        if pending is None:
            raise VerificationError("unknown or already used challenge (replayed presentation?)")
        if self._clock() > pending.expires_at:
            raise VerificationError("challenge expired")
        state["request"] = pending.request
        return "signature covers a fresh, single-use challenge issued by this verifier"

    def _check_requested_claims(self, vp: dict[str, Any], state: dict[str, Any], now: dt.datetime) -> str:
        requested = state["request"]["requestedClaims"]
        disclosed = state["disclosed"]
        missing = [name for name in requested if name not in disclosed]
        if missing:
            raise VerificationError(f"requested claims not disclosed: {', '.join(missing)}")
        if requested:
            state["accepted"] = {name: disclosed[name] for name in requested}
            state["ignored"] = sorted(set(disclosed) - set(requested))
        else:
            state["accepted"], state["ignored"] = dict(disclosed), []
        detail = f"{len(state['accepted'])} claim(s) accepted"
        if state["ignored"]:
            detail += f", {len(state['ignored'])} unrequested claim(s) discarded (data minimisation)"
        return detail
