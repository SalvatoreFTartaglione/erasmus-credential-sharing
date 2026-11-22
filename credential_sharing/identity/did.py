"""DIDs, DID Documents and their resolution against the on-chain registries.

DIDs are *self-certifying*: the method-specific identifier is derived from the
fingerprint of the controller's public key (``did:erasmus:<sha256(SPKI)[:40]>``).
Registries refuse a DID Document whose key does not match its DID, which stops
an attacker from squatting somebody else's identifier.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from credential_sharing.crypto.keys import fingerprint, load_public_key, public_key_to_pem
from credential_sharing.errors import DIDResolutionError

if TYPE_CHECKING:
    from credential_sharing.dlt.accreditation_registry import AccreditationRegistry
    from credential_sharing.dlt.student_did_registry import StudentDIDRegistry

DID_METHOD = "erasmus"
KEY_FRAGMENT = "keys-1"
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
CERTIFICATE_SERVICE_TYPE = "X509CertificateService"


def did_from_public_key(public_key: rsa.RSAPublicKey) -> str:
    return f"did:{DID_METHOD}:{fingerprint(public_key)[:40]}"


def verification_method_id(did: str) -> str:
    return f"{did}#{KEY_FRAGMENT}"


def build_did_document(
    did: str, public_key: rsa.RSAPublicKey, services: Iterable[dict[str, Any]] = ()
) -> dict[str, Any]:
    method_id = verification_method_id(did)
    document: dict[str, Any] = {
        "@context": [DID_CONTEXT],
        "id": did,
        "verificationMethod": [
            {
                "id": method_id,
                "type": "RsaVerificationKey2018",
                "controller": did,
                "publicKeyPem": public_key_to_pem(public_key),
            }
        ],
        "authentication": [method_id],
        "assertionMethod": [method_id],
    }
    services = list(services)
    if services:
        document["service"] = services
    return document


def public_key_from_did_document(
    document: dict[str, Any], method_id: str | None = None
) -> rsa.RSAPublicKey:
    """Return the key of ``method_id`` (or the first one) controlled by the DID subject."""
    for method in document.get("verificationMethod", []):
        if method_id is not None and method.get("id") != method_id:
            continue
        if method.get("controller") != document.get("id") or "publicKeyPem" not in method:
            continue
        try:
            return load_public_key(method["publicKeyPem"])
        except (TypeError, ValueError) as exc:
            raise DIDResolutionError(f"malformed key in {method.get('id')}") from exc
    raise DIDResolutionError(f"no usable verification method {method_id or ''} in DID Document")


def check_did_key_binding(document: dict[str, Any]) -> None:
    """Raise unless the DID is the fingerprint of the key published in its document."""
    did = document.get("id")
    if not isinstance(did, str) or did != did_from_public_key(public_key_from_did_document(document)):
        raise DIDResolutionError("DID does not match the public key in its DID Document")


def add_certificate_service(document: dict[str, Any], certificate: x509.Certificate) -> dict[str, Any]:
    updated = copy.deepcopy(document)
    updated.setdefault("service", []).append(
        {
            "id": f"{document['id']}#x509-certificate",
            "type": CERTIFICATE_SERVICE_TYPE,
            "serviceEndpoint": {
                "certificatePem": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
            },
        }
    )
    return updated


def certificate_from_did_document(document: dict[str, Any]) -> x509.Certificate | None:
    for service in document.get("service", []):
        if service.get("type") != CERTIFICATE_SERVICE_TYPE:
            continue
        pem = service.get("serviceEndpoint", {}).get("certificatePem")
        if pem:
            try:
                return x509.load_pem_x509_certificate(pem.encode("ascii"))
            except ValueError as exc:
                raise DIDResolutionError("malformed X.509 certificate in DID Document") from exc
    return None


class DIDResolver:
    """Resolves DIDs by reading the on-chain registries (a read-only "view" call)."""

    def __init__(
        self, accreditation_registry: AccreditationRegistry, student_registry: StudentDIDRegistry
    ) -> None:
        self._institutions = accreditation_registry
        self._students = student_registry

    def resolve_institution(self, did: str) -> dict[str, Any]:
        document = self._institutions.get_did_document(did)
        if document is None:
            raise DIDResolutionError(f"{did} is not registered in the AccreditationRegistry")
        return document

    def resolve_student(self, did: str) -> dict[str, Any]:
        document = self._students.get_did_document(did)
        if document is None:
            raise DIDResolutionError(f"{did} is not registered in the StudentDIDRegistry")
        return document
