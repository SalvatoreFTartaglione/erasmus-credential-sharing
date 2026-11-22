"""X.509 certificates issued by the Accreditation Entity, acting as root CA.

The AE certificate is the trust anchor of the system and is distributed out of
band. Issuers and verifiers receive an end-entity certificate binding their DID
(Common Name), their role (Organizational Unit) and their public key.
"""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from credential_sharing.crypto.keys import KeyPair, same_public_key
from credential_sharing.errors import CertificateValidationError

ROOT_VALIDITY_DAYS = 10 * 365
ENTITY_VALIDITY_DAYS = 3 * 365


def _now(now: dt.datetime | None) -> dt.datetime:
    return now or dt.datetime.now(dt.timezone.utc)


def create_root_certificate(
    keys: KeyPair, did: str, organisation: str, *, now: dt.datetime | None = None
) -> x509.Certificate:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
            x509.NameAttribute(NameOID.COMMON_NAME, did),
        ]
    )
    start = _now(now)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(keys.public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=ROOT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(keys.public_key), critical=False)
        .sign(keys.private_key, hashes.SHA256())
    )


def issue_certificate(
    *,
    ca_keys: KeyPair,
    ca_certificate: x509.Certificate,
    subject_public_key: rsa.RSAPublicKey,
    subject_did: str,
    role: str,
    now: dt.datetime | None = None,
) -> x509.Certificate:
    start = _now(now)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Accredited {role}"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_did),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=ENTITY_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_keys.public_key), critical=False
        )
        .sign(ca_keys.private_key, hashes.SHA256())
    )


def _single_attribute(name: x509.Name, oid: x509.ObjectIdentifier, label: str) -> str:
    values = name.get_attributes_for_oid(oid)
    if len(values) != 1:
        raise CertificateValidationError(f"certificate must contain exactly one {label}")
    return str(values[0].value)


def validate_certificate(
    certificate: x509.Certificate,
    *,
    ca_certificate: x509.Certificate,
    expected_did: str,
    expected_public_key: rsa.RSAPublicKey,
    expected_role: str,
    now: dt.datetime | None = None,
) -> None:
    """Validate an end-entity certificate against the AE trust anchor.

    Checks issuer name and signature, validity window, that it is not a CA,
    and that DID, role and public key match what the ledger says about the
    entity. Raises :class:`CertificateValidationError` on any mismatch.
    """
    try:
        certificate.verify_directly_issued_by(ca_certificate)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise CertificateValidationError("certificate is not signed by the accreditation CA") from exc

    moment = _now(now)
    if not certificate.not_valid_before_utc <= moment <= certificate.not_valid_after_utc:
        raise CertificateValidationError("certificate is expired or not yet valid")

    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("certificate lacks BasicConstraints") from exc
    if constraints.ca:
        raise CertificateValidationError("an end-entity certificate must not be a CA")

    if _single_attribute(certificate.subject, NameOID.COMMON_NAME, "CN") != expected_did:
        raise CertificateValidationError("certificate subject does not match the DID")
    if _single_attribute(certificate.subject, NameOID.ORGANIZATIONAL_UNIT_NAME, "OU") != expected_role:
        raise CertificateValidationError(f"certificate was not issued for the {expected_role} role")

    subject_key = certificate.public_key()
    if not isinstance(subject_key, rsa.RSAPublicKey) or not same_public_key(subject_key, expected_public_key):
        raise CertificateValidationError("certificate key differs from the DID Document key")
