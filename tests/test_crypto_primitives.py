import datetime as dt

import pytest

from credential_sharing.crypto.keys import KeyPair, verify_signature
from credential_sharing.crypto.secure_channel import SealedMessage, open_sealed, seal
from credential_sharing.errors import CertificateValidationError, ChannelError
from credential_sharing.identity.certificates import (
    create_root_certificate,
    issue_certificate,
    validate_certificate,
)
from credential_sharing.identity.did import did_from_public_key


@pytest.fixture(scope="module")
def keys():
    return {name: KeyPair.generate() for name in ("ca", "other_ca", "alice", "bob", "eve")}


def test_signature_round_trip(keys):
    signature = keys["alice"].sign(b"message")
    assert verify_signature(keys["alice"].public_key, b"message", signature)
    assert not verify_signature(keys["alice"].public_key, b"messagE", signature)
    assert not verify_signature(keys["bob"].public_key, b"message", signature)


def test_secure_channel_round_trip(keys):
    message = seal(b"payload", sender="alice", recipient="bob", recipient_public_key=keys["bob"].public_key)
    assert open_sealed(message, recipient="bob", recipient_keys=keys["bob"]) == b"payload"
    restored = SealedMessage.from_dict(message.to_dict())
    assert open_sealed(restored, recipient="bob", recipient_keys=keys["bob"]) == b"payload"


def test_secure_channel_detects_tampering(keys):
    message = seal(b"payload", sender="alice", recipient="bob", recipient_public_key=keys["bob"].public_key)
    flipped = bytearray(message.ciphertext)
    flipped[0] ^= 1
    tampered = SealedMessage(message.sender, message.recipient, message.wrapped_key, message.nonce, bytes(flipped))
    with pytest.raises(ChannelError):
        open_sealed(tampered, recipient="bob", recipient_keys=keys["bob"])


def test_secure_channel_binds_sender_identity(keys):
    message = seal(b"payload", sender="alice", recipient="bob", recipient_public_key=keys["bob"].public_key)
    spoofed = SealedMessage("eve", message.recipient, message.wrapped_key, message.nonce, message.ciphertext)
    with pytest.raises(ChannelError):
        open_sealed(spoofed, recipient="bob", recipient_keys=keys["bob"])


def test_secure_channel_only_recipient_can_open(keys):
    message = seal(b"payload", sender="alice", recipient="bob", recipient_public_key=keys["bob"].public_key)
    with pytest.raises(ChannelError):
        open_sealed(message, recipient="bob", recipient_keys=keys["eve"])
    with pytest.raises(ChannelError):
        open_sealed(message, recipient="eve", recipient_keys=keys["bob"])


def _entity_cert(keys, *, role="Issuer", ca="ca", subject="alice", now=None):
    ca_did = did_from_public_key(keys[ca].public_key)
    root = create_root_certificate(keys[ca], ca_did, "AE")
    did = did_from_public_key(keys[subject].public_key)
    cert = issue_certificate(ca_keys=keys[ca], ca_certificate=root, subject_public_key=keys[subject].public_key,
                             subject_did=did, role=role, now=now)
    return root, cert, did


def test_certificate_validates_against_its_ca(keys):
    root, cert, did = _entity_cert(keys)
    validate_certificate(cert, ca_certificate=root, expected_did=did,
                         expected_public_key=keys["alice"].public_key, expected_role="Issuer")


@pytest.mark.parametrize("mismatch", ["ca", "did", "key", "role"])
def test_certificate_mismatches_are_rejected(keys, mismatch):
    root, cert, did = _entity_cert(keys)
    expected = {"ca_certificate": root, "expected_did": did,
                "expected_public_key": keys["alice"].public_key, "expected_role": "Issuer"}
    if mismatch == "ca":
        expected["ca_certificate"] = _entity_cert(keys, ca="other_ca")[0]
    elif mismatch == "did":
        expected["expected_did"] = "did:erasmus:someone-else"
    elif mismatch == "key":
        expected["expected_public_key"] = keys["bob"].public_key
    else:
        expected["expected_role"] = "Verifier"
    with pytest.raises(CertificateValidationError):
        validate_certificate(cert, **expected)


def test_expired_certificate_is_rejected(keys):
    long_ago = dt.datetime(2015, 1, 1, tzinfo=dt.timezone.utc)
    root, cert, did = _entity_cert(keys, now=long_ago)
    with pytest.raises(CertificateValidationError, match="expired"):
        validate_certificate(cert, ca_certificate=root, expected_did=did,
                             expected_public_key=keys["alice"].public_key, expected_role="Issuer")
