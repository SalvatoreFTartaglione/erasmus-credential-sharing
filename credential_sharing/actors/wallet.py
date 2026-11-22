"""Student wallet: key custody, credential checks and selective disclosure.

The private key and the credentials are kept encrypted at rest with
AES-256-GCM under a key derived from the user's passphrase with scrypt
(WP2/WP3: protection of the wallet against impersonation and device theft).
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import uuid
from collections.abc import Iterable
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from credential_sharing.actors.issuer import did_binding_payload
from credential_sharing.credential import (
    PRESENTATION_TYPES,
    SIGNED_FIELDS,
    VC_CONTEXT,
    Claim,
    claim_leaf_hash,
    extract_claims,
    sign_document,
)
from credential_sharing.crypto.keys import KeyPair
from credential_sharing.crypto.merkle import MerkleTree
from credential_sharing.crypto.secure_channel import SealedMessage, open_sealed, seal
from credential_sharing.dlt.ledger import Transaction
from credential_sharing.dlt.student_did_registry import StudentDIDRegistry
from credential_sharing.encoding import b64url_decode, b64url_encode, canonical_json, utc_now
from credential_sharing.errors import AuthenticationError, VerificationError, WalletLockedError
from credential_sharing.identity.did import (
    build_did_document,
    did_from_public_key,
    public_key_from_did_document,
    verification_method_id,
)
from credential_sharing.verification import (
    TrustContext,
    check_credential_shape,
    check_status,
    check_validity_period,
    require_accredited,
    verify_issuer_signature,
)

log = logging.getLogger(__name__)


class Wallet:
    KDF_N, KDF_R, KDF_P = 2**14, 8, 1

    def __init__(self, passphrase: str, *, trust: TrustContext) -> None:
        self._trust = trust
        keys = KeyPair.generate()
        self.did = did_from_public_key(keys.public_key)
        self.did_document = build_did_document(self.did, keys.public_key)
        self._kdf_salt = os.urandom(16)
        self._vault = b""
        self._key: bytes | None = self._derive_key(passphrase)
        self._state: dict[str, Any] | None = {"privateKey": keys.to_pem().decode(), "credentials": []}
        self._keypair: KeyPair | None = None
        self.lock()

    # -- encryption at rest --------------------------------------------------

    def _derive_key(self, passphrase: str) -> bytes:
        return hashlib.scrypt(
            passphrase.encode(), salt=self._kdf_salt, n=self.KDF_N, r=self.KDF_R, p=self.KDF_P, dklen=32
        )

    @property
    def is_unlocked(self) -> bool:
        return self._state is not None

    def lock(self) -> None:
        if self._state is None or self._key is None:
            return
        nonce = os.urandom(12)
        self._vault = nonce + AESGCM(self._key).encrypt(nonce, canonical_json(self._state), self.did.encode())
        self._state = None
        self._key = None
        self._keypair = None

    def unlock(self, passphrase: str) -> None:
        key = self._derive_key(passphrase)
        try:
            plaintext = AESGCM(key).decrypt(self._vault[:12], self._vault[12:], self.did.encode())
        except InvalidTag as exc:
            raise AuthenticationError("wrong wallet passphrase") from exc
        self._state = json.loads(plaintext)
        self._key = key
        self._keypair = KeyPair.from_pem(self._state["privateKey"].encode())

    def _unlocked_state(self) -> dict[str, Any]:
        if self._state is None:
            raise WalletLockedError("unlock the wallet first")
        return self._state

    def _keys(self) -> KeyPair:
        if self._keypair is None:
            raise WalletLockedError("unlock the wallet first")
        return self._keypair

    # -- identity --------------------------------------------------------------

    def register_did(self, registry: StudentDIDRegistry) -> None:
        registry.register(
            Transaction(
                contract=registry.name,
                method="register",
                params={"didDocument": self.did_document},
                sender=self.did,
            ).signed_by(self._keys())
        )
        log.info("Wallet: DID %s registered on the StudentDIDRegistry", self.did)

    def sign_did_binding(self, issuer_did: str, nonce: str) -> str:
        return b64url_encode(self._keys().sign(did_binding_payload(issuer_did, self.did, nonce)))

    # -- credentials (phase 2, end of step 5) ------------------------------------

    def accept_credential(self, message: SealedMessage, *, now: dt.datetime | None = None) -> dict[str, Any]:
        state = self._unlocked_state()
        credential = json.loads(open_sealed(message, recipient=self.did, recipient_keys=self._keys()))
        if message.sender != credential.get("issuer", {}).get("id"):
            raise VerificationError("credential was not sent by its issuer")
        self.verify_credential(credential, now=now)
        state["credentials"].append(credential)
        log.info("Wallet: credential %s verified and stored", credential["id"])
        return copy.deepcopy(credential)

    def verify_credential(self, credential: dict[str, Any], *, now: dt.datetime | None = None) -> None:
        """Integrity, authenticity, holder binding, accreditation, validity and status."""
        now = now or utc_now()
        check_credential_shape(credential)
        if credential["credentialSubject"]["id"] != self.did:
            raise VerificationError("credential was issued to another DID")
        issuer_document = require_accredited(self._trust, credential["issuer"]["id"], "Issuer", now=now)
        verify_issuer_signature(credential, issuer_document)

        claims = extract_claims(credential["credentialSubject"])
        salts = credential.get("disclosureSalts", {})
        if set(salts) != {name for name, _ in claims}:
            raise VerificationError("disclosure salts do not match the credential claims")
        tree = MerkleTree([claim_leaf_hash(name, salts[name], value) for name, value in claims])
        if not hmac.compare_digest(tree.root, b64url_decode(credential["proof"]["merkleRoot"])):
            raise VerificationError("Merkle root does not match the credential content")

        check_validity_period(credential, now)
        check_status(self._trust, credential)

    @property
    def credentials(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._unlocked_state()["credentials"])

    def disclosable_claims(self, index: int = 0) -> list[Claim]:
        return extract_claims(self._unlocked_state()["credentials"][index]["credentialSubject"])

    # -- presentation (phase 3, step 6) -----------------------------------------

    def create_presentation(
        self, request: dict[str, Any], claim_names: Iterable[str], *, index: int = 0
    ) -> dict[str, Any]:
        """Build a presentation revealing only ``claim_names``, bound to ``request``."""
        credential = self._unlocked_state()["credentials"][index]
        claims = extract_claims(credential["credentialSubject"])
        wanted = set(claim_names)
        unknown = wanted - {name for name, _ in claims}
        if unknown:
            raise ValueError(f"unknown claims: {', '.join(sorted(unknown))}")
        if not wanted:
            raise ValueError("select at least one claim to disclose")

        salts = credential["disclosureSalts"]
        tree = MerkleTree([claim_leaf_hash(name, salts[name], value) for name, value in claims])
        derived = {field: copy.deepcopy(credential[field]) for field in SIGNED_FIELDS}
        derived["credentialSubject"] = {"id": credential["credentialSubject"]["id"]}
        derived["disclosedClaims"] = [
            {"name": name, "salt": salts[name], "value": value, "proof": tree.proof(position)}
            for position, (name, value) in enumerate(claims)
            if name in wanted
        ]
        derived["proof"] = copy.deepcopy(credential["proof"])
        presentation = {
            "@context": [VC_CONTEXT],
            "type": list(PRESENTATION_TYPES),
            "id": f"urn:uuid:{uuid.uuid4()}",
            "holder": self.did,
            "verifiableCredential": [derived],
        }
        return self.sign_presentation(presentation, challenge=request["challenge"], domain=request["domain"])

    def sign_presentation(self, presentation: dict[str, Any], *, challenge: str, domain: str) -> dict[str, Any]:
        unsigned = copy.deepcopy(presentation)
        unsigned.pop("proof", None)
        return sign_document(
            unsigned,
            self._keys(),
            verification_method=verification_method_id(self.did),
            proof_purpose="authentication",
            challenge=challenge,
            domain=domain,
        )

    def send_presentation(
        self, presentation: dict[str, Any], verifier_did: str, *, now: dt.datetime | None = None
    ) -> SealedMessage:
        """Encrypt the presentation for ``verifier_did`` after checking it is an accredited verifier."""
        if presentation["proof"]["domain"] != verifier_did:
            raise ValueError("presentation was created for a different verifier")
        document = require_accredited(self._trust, verifier_did, "Verifier", now=now)
        log.info("Wallet: verifier %s is accredited, sending the presentation", verifier_did)
        return seal(
            canonical_json(presentation),
            sender=self.did,
            recipient=verifier_did,
            recipient_public_key=public_key_from_did_document(document),
        )
