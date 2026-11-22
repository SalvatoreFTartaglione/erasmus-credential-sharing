"""Accreditation Entity (AE): root of trust of the system (WP2, phase 1)."""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from cryptography import x509

from credential_sharing.credential import VC_CONTEXT, sign_document
from credential_sharing.crypto.keys import KeyPair, verify_signature
from credential_sharing.dlt.accreditation_registry import AccreditationRegistry
from credential_sharing.dlt.ledger import Ledger, Transaction
from credential_sharing.encoding import b64url_decode, canonical_json, format_timestamp, utc_now
from credential_sharing.errors import AuthenticationError, DIDResolutionError
from credential_sharing.identity.certificates import create_root_certificate, issue_certificate
from credential_sharing.identity.did import (
    add_certificate_service,
    build_did_document,
    check_did_key_binding,
    did_from_public_key,
    public_key_from_did_document,
    verification_method_id,
)

log = logging.getLogger(__name__)

ACCREDITATION_VALIDITY = dt.timedelta(days=3 * 365)


@dataclass(frozen=True)
class AccreditationRequest:
    """Request sent by a university, signed with the key it wants accredited."""

    name: str
    role: str
    did_document: dict[str, Any]
    proof: str  # base64url RSA-PSS signature over :meth:`payload` (proof of possession)

    @staticmethod
    def payload(name: str, role: str, did_document: dict[str, Any]) -> bytes:
        return canonical_json({"name": name, "role": role, "didDocument": did_document})


@dataclass(frozen=True)
class AccreditationGrant:
    certificate: x509.Certificate
    did_document: dict[str, Any]
    credential: dict[str, Any]


class AccreditationEntity:
    """Certification authority for institutions and sole writer of the AccreditationRegistry."""

    def __init__(self, name: str, ledger: Ledger, *, recognised_institutions: Iterable[str]) -> None:
        self.name = name
        self._keys = KeyPair.generate()
        self.did = did_from_public_key(self._keys.public_key)
        self.did_document = build_did_document(
            self.did,
            self._keys.public_key,
            services=[{
                "id": f"{self.did}#accreditation",
                "type": "AccreditationRequestService",
                "serviceEndpoint": "https://accreditation.example.org/requests",
            }],
        )
        self.ca_certificate = create_root_certificate(self._keys, self.did, name)
        self.registry = AccreditationRegistry(ledger, self.did, self._keys.public_key)
        self._recognised = frozenset(recognised_institutions)
        log.info("AE %s ready: root certificate issued, AccreditationRegistry deployed", self.did)

    @property
    def public_key(self):
        return self._keys.public_key

    def handle_accreditation_request(self, request: AccreditationRequest) -> AccreditationGrant:
        """Phases 2a/2b (technical and institutional checks) and 3a/3b (accreditation)."""
        if request.role not in AccreditationRegistry.ROLES:
            raise ValueError(f"unsupported role {request.role!r}")
        try:
            check_did_key_binding(request.did_document)
            public_key = public_key_from_did_document(request.did_document)
            proof = b64url_decode(request.proof)
        except (DIDResolutionError, ValueError) as exc:
            raise AuthenticationError(f"malformed accreditation request: {exc}") from exc
        payload = AccreditationRequest.payload(request.name, request.role, request.did_document)
        if not verify_signature(public_key, payload, proof):
            raise AuthenticationError("proof of possession of the private key failed")
        if request.name not in self._recognised:
            raise AuthenticationError(f"{request.name} is not a recognised institution")

        did = request.did_document["id"]
        certificate = issue_certificate(
            ca_keys=self._keys,
            ca_certificate=self.ca_certificate,
            subject_public_key=public_key,
            subject_did=did,
            role=request.role,
        )
        document = add_certificate_service(request.did_document, certificate)
        self.registry.accredit(
            Transaction(
                contract=self.registry.name,
                method="accredit",
                params={"didDocument": document, "role": request.role},
                sender=self.did,
            ).signed_by(self._keys)
        )
        log.info("AE: %s accredited as %s (%s)", request.name, request.role, did)
        return AccreditationGrant(certificate, document, self._accreditation_credential(request, did))

    def revoke_accreditation(self, did: str, reason: str) -> None:
        self.registry.revoke(
            Transaction(
                contract=self.registry.name,
                method="revoke",
                params={"did": did, "reason": reason},
                sender=self.did,
            ).signed_by(self._keys)
        )
        log.info("AE: accreditation of %s revoked (%s)", did, reason)

    def _accreditation_credential(self, request: AccreditationRequest, did: str) -> dict[str, Any]:
        now = utc_now()
        credential = {
            "@context": [VC_CONTEXT],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "AccreditationCredential"],
            "issuer": self.did,
            "issuanceDate": format_timestamp(now),
            "expirationDate": format_timestamp(now + ACCREDITATION_VALIDITY),
            "credentialSubject": {
                "id": did,
                "name": request.name,
                "role": request.role,
                "accreditationStatus": "Accredited",
            },
        }
        return sign_document(
            credential,
            self._keys,
            verification_method=verification_method_id(self.did),
            proof_purpose="assertionMethod",
        )
