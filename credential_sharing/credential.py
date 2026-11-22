"""Credential format: disclosable claims, salted Merkle leaves and signing inputs.

Selective disclosure works as follows (WP2, phase 2-3):

1. The ``credentialSubject`` is split into independently disclosable *claims*
   (:func:`extract_claims`): one per personal attribute and one per course.
2. Each claim gets a fresh 128-bit random salt and becomes a Merkle leaf
   ``H(0x00 || canonical({name, salt, value}))``. Salting is what prevents a
   verifier from brute-forcing undisclosed values (e.g. a grade, which has only
   a handful of possible values) from the sibling hashes in a Merkle proof.
3. The issuer signs the Merkle root **together with** the credential metadata
   (id, issuer, dates, status entry) and the holder's DID, so none of them can
   be altered and the credential is bound to its holder.
4. In a presentation the holder reveals only the chosen claims, each with its
   salt and Merkle proof; the verifier recomputes the root and checks the
   issuer signature over it.
"""

from __future__ import annotations

import copy
import secrets
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from credential_sharing.crypto.keys import KeyPair, verify_signature
from credential_sharing.crypto.merkle import hash_leaf
from credential_sharing.encoding import (
    b64url_decode,
    b64url_encode,
    canonical_json,
    format_timestamp,
    utc_now,
)
from credential_sharing.errors import VerificationError

VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
CREDENTIAL_TYPES = ["VerifiableCredential", "ErasmusMobilityCredential"]
PRESENTATION_TYPES = ["VerifiablePresentation"]
MERKLE_PROOF_TYPE = "MerkleSelectiveDisclosure2025"
DOCUMENT_PROOF_TYPE = "RsaPssSignature2025"

#: Top-level credential fields covered by the issuer signature.
SIGNED_FIELDS = ("@context", "id", "type", "issuer", "issuanceDate", "expirationDate", "credentialStatus")
#: Proof fields covered by the issuer signature.
SIGNED_PROOF_FIELDS = ("type", "created", "verificationMethod", "proofPurpose", "merkleRoot")

Claim = tuple[str, Any]


def extract_claims(subject: dict[str, Any]) -> list[Claim]:
    """Split a ``credentialSubject`` into disclosable ``(name, value)`` claims.

    The order is deterministic, so issuer and holder build the same tree. The
    subject ``id`` is not a claim: it is always bound through the signature.
    """
    claims: list[Claim] = []
    for key in sorted(subject):
        value = subject[key]
        if key == "id":
            continue
        if key == "learningAgreement":
            claims.append(("learningAgreement.semester", value["semester"]))
            claims.extend(
                (f"learningAgreement.agreedCourses.{course['id']}", course)
                for course in value["agreedCourses"]
            )
        elif key == "optionalExperience":
            for item in sorted(value):
                if item == "optionalCourses":
                    claims.extend(
                        (f"optionalExperience.optionalCourses.{course['id']}", course)
                        for course in value[item]
                    )
                else:
                    claims.append((f"optionalExperience.{item}", value[item]))
        else:
            claims.append((key, value))
    names = [name for name, _ in claims]
    if len(names) != len(set(names)):
        raise ValueError("claim names must be unique (duplicate course ids?)")
    return claims


def new_salt() -> str:
    return b64url_encode(secrets.token_bytes(16))


def claim_leaf_hash(name: str, salt: str, value: Any) -> bytes:
    return hash_leaf(canonical_json({"name": name, "salt": salt, "value": value}))


def credential_signing_input(credential: dict[str, Any]) -> bytes:
    """Bytes signed by the issuer. Identical for a full VC and a derived one."""
    return canonical_json(
        {
            "credential": {field: credential[field] for field in SIGNED_FIELDS},
            "subject": credential["credentialSubject"]["id"],
            "proof": {field: credential["proof"][field] for field in SIGNED_PROOF_FIELDS},
        }
    )


# -- generic signed JSON documents (accreditation VCs, presentations) --------


def document_signing_input(document: dict[str, Any]) -> bytes:
    unsigned = copy.deepcopy(document)
    unsigned["proof"].pop("signatureValue", None)
    return canonical_json(unsigned)


def sign_document(
    document: dict[str, Any],
    keys: KeyPair,
    *,
    verification_method: str,
    proof_purpose: str,
    **proof_fields: Any,
) -> dict[str, Any]:
    """Return a copy of ``document`` with an RSA-PSS proof over all of its content."""
    signed = copy.deepcopy(document)
    signed["proof"] = {
        "type": DOCUMENT_PROOF_TYPE,
        "created": format_timestamp(utc_now()),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
        **proof_fields,
    }
    signed["proof"]["signatureValue"] = b64url_encode(keys.sign(document_signing_input(signed)))
    return signed


def verify_document(document: dict[str, Any], public_key: rsa.RSAPublicKey) -> bool:
    try:
        signature = b64url_decode(document["proof"]["signatureValue"])
        return verify_signature(public_key, document_signing_input(document), signature)
    except (KeyError, TypeError, ValueError):
        return False


def verify_accreditation_credential(
    credential: dict[str, Any],
    *,
    authority_did: str,
    authority_key: rsa.RSAPublicKey,
    subject_did: str,
    role: str,
) -> None:
    """Check the AccreditationCredential an institution receives from the AE."""
    subject = credential.get("credentialSubject", {})
    if credential.get("issuer") != authority_did:
        raise VerificationError("accreditation credential not issued by the Accreditation Entity")
    if subject.get("id") != subject_did or subject.get("role") != role:
        raise VerificationError("accreditation credential refers to another entity or role")
    if not verify_document(credential, authority_key):
        raise VerificationError("invalid signature on the accreditation credential")
