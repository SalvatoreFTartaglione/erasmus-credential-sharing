"""RSA key pairs, RSA-PSS signatures and RSA-OAEP key transport.

RSA-2048 is used to stay consistent with the X.509-based design described in
the project report. The README discusses Ed25519 and BBS+ as alternatives.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class KeyPair:
    """An RSA key pair able to sign (RSA-PSS/SHA-256) and to unwrap keys (RSA-OAEP)."""

    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls, key_size: int = RSA_KEY_SIZE) -> KeyPair:
        return cls(rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size))

    @classmethod
    def from_pem(cls, pem: bytes, passphrase: bytes | None = None) -> KeyPair:
        key = serialization.load_pem_private_key(pem, password=passphrase)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("only RSA private keys are supported")
        return cls(key)

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._private_key.public_key()

    @property
    def public_pem(self) -> str:
        return public_key_to_pem(self.public_key)

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Raw key object, exposed only to sign X.509 certificates."""
        return self._private_key

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, _PSS, hashes.SHA256())

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._private_key.decrypt(ciphertext, _OAEP)

    def to_pem(self, passphrase: bytes | None = None) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )
        return self._private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def load_public_key(pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("only RSA public keys are supported")
    return key


def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data, _PSS, hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def encrypt_for(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    return public_key.encrypt(plaintext, _OAEP)


def _spki_der(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 of the DER-encoded SubjectPublicKeyInfo, hex encoded."""
    return hashlib.sha256(_spki_der(public_key)).hexdigest()


def same_public_key(a: rsa.RSAPublicKey, b: rsa.RSAPublicKey) -> bool:
    return _spki_der(a) == _spki_der(b)
