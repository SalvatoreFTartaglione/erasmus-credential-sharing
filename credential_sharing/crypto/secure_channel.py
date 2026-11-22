"""Hybrid authenticated encryption that models the TLS channels of the design.

The protocol assumes that every exchange happens over TLS. Implementing TLS is
out of scope, so this module reproduces the guarantees the protocol relies on:

* **confidentiality and integrity** of the payload with AES-256-GCM (an AEAD;
  the first version used AES-CBC without a MAC, which is malleable);
* **recipient authentication**: a fresh content key is wrapped with RSA-OAEP
  under the recipient's public key. Callers must take that key from the ledger
  and validate it through the recipient's X.509 certificate, never trust a key
  handed over by the peer itself;
* **context binding**: sender and recipient DIDs are authenticated as
  associated data, so a message cannot be silently re-routed to another party.

Sender authentication is provided one layer up, by the signatures carried in
credentials and presentations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from credential_sharing.crypto.keys import KeyPair, encrypt_for
from credential_sharing.encoding import b64url_decode, b64url_encode, canonical_json
from credential_sharing.errors import ChannelError

_NONCE_SIZE = 12


@dataclass(frozen=True)
class SealedMessage:
    sender: str
    recipient: str
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "wrappedKey": b64url_encode(self.wrapped_key),
            "nonce": b64url_encode(self.nonce),
            "ciphertext": b64url_encode(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> SealedMessage:
        return cls(
            sender=data["sender"],
            recipient=data["recipient"],
            wrapped_key=b64url_decode(data["wrappedKey"]),
            nonce=b64url_decode(data["nonce"]),
            ciphertext=b64url_decode(data["ciphertext"]),
        )

    @property
    def size(self) -> int:
        """Size in bytes of the message as sent on the wire (canonical JSON)."""
        return len(canonical_json(self.to_dict()))


def _associated_data(sender: str, recipient: str) -> bytes:
    return canonical_json({"sender": sender, "recipient": recipient})


def seal(
    plaintext: bytes, *, sender: str, recipient: str, recipient_public_key: rsa.RSAPublicKey
) -> SealedMessage:
    content_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(content_key).encrypt(nonce, plaintext, _associated_data(sender, recipient))
    return SealedMessage(
        sender=sender,
        recipient=recipient,
        wrapped_key=encrypt_for(recipient_public_key, content_key),
        nonce=nonce,
        ciphertext=ciphertext,
    )


def open_sealed(message: SealedMessage, *, recipient: str, recipient_keys: KeyPair) -> bytes:
    if message.recipient != recipient:
        raise ChannelError("message is addressed to another party")
    try:
        content_key = recipient_keys.decrypt(message.wrapped_key)
        return AESGCM(content_key).decrypt(
            message.nonce, message.ciphertext, _associated_data(message.sender, message.recipient)
        )
    except (InvalidTag, ValueError) as exc:
        raise ChannelError("message failed authentication: it was tampered with or mis-routed") from exc
