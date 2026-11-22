"""Issuer (Université de Rennes): authenticates students and issues credentials (WP2, phase 2)."""

from __future__ import annotations

import copy
import datetime as dt
import logging
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from credential_sharing.actors.institution import Institution
from credential_sharing.auth import Clock, OtpService, PasswordHasher, Throttle
from credential_sharing.credential import (
    CREDENTIAL_TYPES,
    MERKLE_PROOF_TYPE,
    VC_CONTEXT,
    claim_leaf_hash,
    credential_signing_input,
    extract_claims,
    new_salt,
)
from credential_sharing.crypto.keys import verify_signature
from credential_sharing.crypto.merkle import MerkleTree
from credential_sharing.crypto.secure_channel import SealedMessage, seal
from credential_sharing.dlt.credential_status_registry import CredentialStatusRegistry
from credential_sharing.dlt.ledger import Transaction
from credential_sharing.dlt.student_did_registry import StudentDIDRegistry
from credential_sharing.encoding import (
    b64url_decode,
    b64url_encode,
    canonical_json,
    format_timestamp,
    utc_now,
)
from credential_sharing.errors import AuthenticationError
from credential_sharing.identity.did import public_key_from_did_document, verification_method_id

log = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 15 * 60
CREDENTIAL_VALIDITY = dt.timedelta(days=3 * 365)


def did_binding_payload(issuer_did: str, holder_did: str, nonce: str) -> bytes:
    """Message the wallet signs to prove it controls the DID it asks the credential for."""
    return canonical_json(
        {"purpose": "did-binding", "issuer": issuer_did, "holder": holder_did, "nonce": nonce}
    )


@dataclass
class StudentAccount:
    email: str
    password_hash: str
    record: dict[str, Any]
    holder_did: str | None = None


@dataclass
class _Session:
    email: str
    expires_at: float
    binding_nonce: str | None = None


class Issuer(Institution):
    role = "Issuer"
    service_type = "IssuerService"

    def __init__(
        self,
        name: str,
        *,
        status_registry: CredentialStatusRegistry,
        student_registry: StudentDIDRegistry,
        otp_delivery: Callable[[str, str], None],
        clock: Clock = time.monotonic,
    ) -> None:
        super().__init__(name)
        self._status_registry = status_registry
        self._student_registry = student_registry
        self._clock = clock
        self._otp = OtpService(otp_delivery, clock=clock)
        self._throttle = Throttle(clock=clock)
        self._accounts: dict[str, StudentAccount] = {}
        self._sessions: dict[str, _Session] = {}
        self._issued: list[dict[str, str]] = []

    # -- student portal: authentication (phase 2, step 4) --------------------

    def enroll_student(self, email: str, password: str, record: dict[str, Any]) -> None:
        """Back-office operation: the student's academic record and portal password."""
        self._accounts[email] = StudentAccount(email, PasswordHasher.hash(password), copy.deepcopy(record))

    def begin_login(self, email: str, password: str) -> None:
        """First factor. On success an OTP is sent to the student's registered address."""
        self._throttle.check(email)
        account = self._accounts.get(email)
        if account is None or not PasswordHasher.verify(password, account.password_hash):
            self._throttle.failure(email)
            raise AuthenticationError("invalid e-mail or password")
        self._otp.issue(email, email)
        log.info("%s: password accepted, one-time password sent to %s", self.name, email)

    def complete_login(self, email: str, otp: str) -> str:
        """Second factor. Returns a session token."""
        self._throttle.check(email)
        if not self._otp.verify(email, otp):
            self._throttle.failure(email)
            raise AuthenticationError("invalid or expired one-time password")
        self._throttle.success(email)
        token = secrets.token_urlsafe(32)
        self._sessions[token] = _Session(email, self._clock() + SESSION_TTL_SECONDS)
        log.info("%s: %s authenticated (password + OTP)", self.name, email)
        return token

    def retry_after(self, email: str) -> float:
        return self._throttle.retry_after(email)

    def _session(self, token: str) -> _Session:
        session = self._sessions.get(token)
        if session is None or self._clock() > session.expires_at:
            self._sessions.pop(token, None)
            raise AuthenticationError("session missing or expired")
        return session

    # -- binding the student's DID to the account ------------------------------

    def start_did_binding(self, token: str) -> str:
        session = self._session(token)
        session.binding_nonce = secrets.token_urlsafe(16)
        return session.binding_nonce

    def bind_holder_did(self, token: str, holder_did: str, signature: str) -> None:
        """Accept ``holder_did`` only if the student proves possession of its key."""
        session = self._session(token)
        nonce, session.binding_nonce = session.binding_nonce, None
        if nonce is None:
            raise AuthenticationError("no DID binding in progress")
        document = self._student_registry.get_did_document(holder_did)
        if document is None:
            raise AuthenticationError("holder DID is not registered on the ledger")
        payload = did_binding_payload(self.did, holder_did, nonce)
        if not verify_signature(public_key_from_did_document(document), payload, b64url_decode(signature)):
            raise AuthenticationError("proof of possession of the holder key failed")
        self._accounts[session.email].holder_did = holder_did
        log.info("%s: DID %s bound to %s", self.name, holder_did, session.email)

    # -- issuance (phase 2, step 5) ------------------------------------------

    def issue_credential(self, token: str) -> SealedMessage:
        account = self._accounts[self._session(token).email]
        if account.holder_did is None:
            raise AuthenticationError("bind a DID to the account before requesting a credential")
        credential = self._build_credential(account)
        status_id = credential["credentialStatus"]["statusId"]
        self._status_registry.register(
            Transaction(
                contract=self._status_registry.name,
                method="register",
                params={"statusId": status_id},
                sender=self.did,
            ).signed_by(self._keys)
        )
        self._issued.append({"credentialId": credential["id"], "statusId": status_id, "holder": account.holder_did})
        log.info("%s: credential %s issued and registered as Valid on the ledger", self.name, credential["id"])

        holder_document = self._student_registry.get_did_document(account.holder_did)
        return seal(
            canonical_json(credential),
            sender=self.did,
            recipient=account.holder_did,
            recipient_public_key=public_key_from_did_document(holder_document),
        )

    def _build_credential(self, account: StudentAccount) -> dict[str, Any]:
        now = utc_now()
        subject = {"id": account.holder_did, **copy.deepcopy(account.record)}
        claims = extract_claims(subject)
        salts = {name: new_salt() for name, _ in claims}
        tree = MerkleTree([claim_leaf_hash(name, salts[name], value) for name, value in claims])
        root = b64url_encode(tree.root)
        credential: dict[str, Any] = {
            "@context": [VC_CONTEXT],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": list(CREDENTIAL_TYPES),
            "issuer": {"id": self.did, "name": self.name},
            "issuanceDate": format_timestamp(now),
            "expirationDate": format_timestamp(now + CREDENTIAL_VALIDITY),
            "credentialSubject": subject,
            "credentialStatus": {
                "id": f"urn:credential-status:{root}",
                "type": "LedgerCredentialStatus2025",
                "statusRegistry": CredentialStatusRegistry.name,
                "statusId": root,
            },
            "proof": {
                "type": MERKLE_PROOF_TYPE,
                "created": format_timestamp(now),
                "verificationMethod": verification_method_id(self.did),
                "proofPurpose": "assertionMethod",
                "merkleRoot": root,
            },
            # Holder-only secrets: one salt per claim, never shared in full.
            "disclosureSalts": salts,
        }
        credential["proof"]["signatureValue"] = b64url_encode(
            self._keys.sign(credential_signing_input(credential))
        )
        return credential

    # -- revocation (phase 4) ------------------------------------------------

    @property
    def issued_credentials(self) -> list[dict[str, str]]:
        return [dict(entry) for entry in self._issued]

    def revoke_credential(self, status_id: str, reason: str) -> None:
        self._status_registry.revoke(
            Transaction(
                contract=self._status_registry.name,
                method="revoke",
                params={"statusId": status_id, "reason": reason},
                sender=self.did,
            ).signed_by(self._keys)
        )
        log.info("%s: credential %s... revoked (%s)", self.name, status_id[:16], reason)
