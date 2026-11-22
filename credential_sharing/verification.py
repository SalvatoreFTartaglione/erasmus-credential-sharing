"""Checks shared by the student's wallet and the verifier.

Both parties must establish the same facts about a credential before trusting
it (WP2, phases 2 and 3): the issuer is an *accredited issuer* with a valid
certificate chaining to the AE, the issuer signature is valid, the credential
is within its validity period and has not been revoked on the ledger.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from cryptography import x509

from credential_sharing.credential import (
    SIGNED_FIELDS,
    SIGNED_PROOF_FIELDS,
    credential_signing_input,
)
from credential_sharing.crypto.keys import verify_signature
from credential_sharing.dlt.accreditation_registry import ACCREDITED, AccreditationRegistry
from credential_sharing.dlt.credential_status_registry import VALID, CredentialStatusRegistry
from credential_sharing.encoding import b64url_decode, parse_timestamp
from credential_sharing.errors import CertificateValidationError, DIDResolutionError, VerificationError
from credential_sharing.identity.certificates import validate_certificate
from credential_sharing.identity.did import (
    DIDResolver,
    certificate_from_did_document,
    public_key_from_did_document,
)


@dataclass(frozen=True)
class TrustContext:
    """Everything a party needs to evaluate credentials without contacting the issuer."""

    resolver: DIDResolver
    accreditation_registry: AccreditationRegistry
    status_registry: CredentialStatusRegistry
    trust_anchor: x509.Certificate  # AE root certificate, distributed out of band


def require_accredited(
    trust: TrustContext, did: str, role: str, *, now: dt.datetime | None = None
) -> dict[str, Any]:
    """Return the DID Document of ``did`` if it is currently accredited for ``role``."""
    record = trust.accreditation_registry.get_record(did)
    if record is None:
        raise VerificationError(f"{did} is not registered in the AccreditationRegistry")
    if record["role"] != role:
        raise VerificationError(f"{did} is accredited as {record['role']}, not as {role}")
    if record["status"] != ACCREDITED:
        raise VerificationError(f"accreditation of {did} is {record['status']}")
    try:
        document = trust.resolver.resolve_institution(did)
        certificate = certificate_from_did_document(document)
        if certificate is None:
            raise VerificationError(f"DID Document of {did} has no X.509 certificate")
        validate_certificate(
            certificate,
            ca_certificate=trust.trust_anchor,
            expected_did=did,
            expected_public_key=public_key_from_did_document(document),
            expected_role=role,
            now=now,
        )
    except (CertificateValidationError, DIDResolutionError) as exc:
        raise VerificationError(str(exc)) from exc
    return document


def check_credential_shape(credential: dict[str, Any]) -> None:
    missing = [field for field in SIGNED_FIELDS if field not in credential]
    missing += [f"proof.{field}" for field in (*SIGNED_PROOF_FIELDS, "signatureValue")
                if field not in credential.get("proof", {})]
    if not isinstance(credential.get("credentialSubject", {}).get("id"), str):
        missing.append("credentialSubject.id")
    if missing:
        raise VerificationError(f"credential is missing fields: {', '.join(missing)}")


def verify_issuer_signature(credential: dict[str, Any], issuer_document: dict[str, Any]) -> None:
    issuer_did = credential["issuer"]["id"]
    method = credential["proof"]["verificationMethod"]
    if not method.startswith(issuer_did + "#"):
        raise VerificationError("verification method does not belong to the issuer")
    try:
        key = public_key_from_did_document(issuer_document, method)
        signature = b64url_decode(credential["proof"]["signatureValue"])
    except (DIDResolutionError, ValueError) as exc:
        raise VerificationError(f"cannot check the issuer signature: {exc}") from exc
    if not verify_signature(key, credential_signing_input(credential), signature):
        raise VerificationError("issuer signature is invalid: the credential was altered")


def check_validity_period(credential: dict[str, Any], now: dt.datetime) -> None:
    try:
        issued = parse_timestamp(credential["issuanceDate"])
        expires = parse_timestamp(credential["expirationDate"])
    except ValueError as exc:
        raise VerificationError("malformed credential dates") from exc
    if now < issued:
        raise VerificationError("credential is not valid yet")
    if now > expires:
        raise VerificationError("credential has expired")


def check_status(trust: TrustContext, credential: dict[str, Any]) -> None:
    status_id = credential["credentialStatus"]["statusId"]
    entry = trust.status_registry.get_status(status_id)
    if entry is None:
        raise VerificationError("credential is unknown to the CredentialStatusRegistry")
    if entry["issuer"] != credential["issuer"]["id"]:
        raise VerificationError("status entry was registered by a different issuer")
    if entry["status"] != VALID:
        raise VerificationError(f"credential status is {entry['status']}")
