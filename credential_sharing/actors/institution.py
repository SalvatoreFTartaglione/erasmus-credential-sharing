"""Common behaviour of universities that must be accredited (issuer and verifier)."""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any, ClassVar

from cryptography import x509

from credential_sharing.actors.accreditation_entity import AccreditationEntity, AccreditationRequest
from credential_sharing.credential import verify_accreditation_credential
from credential_sharing.crypto.keys import KeyPair
from credential_sharing.encoding import b64url_encode
from credential_sharing.identity.certificates import validate_certificate
from credential_sharing.identity.did import (
    build_did_document,
    did_from_public_key,
    public_key_from_did_document,
)

log = logging.getLogger(__name__)


def slugify(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")


class Institution:
    role: ClassVar[str]
    service_type: ClassVar[str]

    def __init__(self, name: str) -> None:
        self.name = name
        self._keys = KeyPair.generate()
        self.did = did_from_public_key(self._keys.public_key)
        self.did_document: dict[str, Any] = build_did_document(
            self.did,
            self._keys.public_key,
            services=[{
                "id": f"{self.did}#{self.role.lower()}-service",
                "type": self.service_type,
                "serviceEndpoint": f"https://{slugify(name)}.example.org/{self.role.lower()}",
            }],
        )
        self.certificate: x509.Certificate | None = None
        self.accreditation_credential: dict[str, Any] | None = None

    @property
    def public_key(self):
        return self._keys.public_key

    @property
    def is_accredited(self) -> bool:
        return self.certificate is not None

    def build_accreditation_request(self) -> AccreditationRequest:
        payload = AccreditationRequest.payload(self.name, self.role, self.did_document)
        return AccreditationRequest(
            name=self.name,
            role=self.role,
            did_document=self.did_document,
            proof=b64url_encode(self._keys.sign(payload)),
        )

    def request_accreditation(self, authority: AccreditationEntity) -> None:
        """Phase 1a/1b: ask the AE for accreditation and check what comes back."""
        log.info("%s: requesting accreditation as %s", self.name, self.role)
        grant = authority.handle_accreditation_request(self.build_accreditation_request())
        validate_certificate(
            grant.certificate,
            ca_certificate=authority.ca_certificate,
            expected_did=self.did,
            expected_public_key=self.public_key,
            expected_role=self.role,
        )
        verify_accreditation_credential(
            grant.credential,
            authority_did=authority.did,
            authority_key=public_key_from_did_document(authority.did_document),
            subject_did=self.did,
            role=self.role,
        )
        self.certificate = grant.certificate
        self.did_document = grant.did_document
        self.accreditation_credential = grant.credential
        log.info("%s: X.509 certificate and AccreditationCredential verified", self.name)
