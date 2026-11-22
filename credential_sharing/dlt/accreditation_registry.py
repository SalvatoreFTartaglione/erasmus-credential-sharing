"""AccreditationRegistry: DID Documents and accreditation status of issuers/verifiers."""

from __future__ import annotations

import copy
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from credential_sharing.crypto.keys import public_key_to_pem
from credential_sharing.dlt.ledger import Ledger, SmartContract, Transaction
from credential_sharing.encoding import format_timestamp, utc_now
from credential_sharing.errors import DIDResolutionError, UnauthorizedTransactionError
from credential_sharing.identity.did import (
    check_did_key_binding,
    did_from_public_key,
    public_key_from_did_document,
)

ACCREDITED = "Accredited"
REVOKED = "Revoked"


class AccreditationRegistry(SmartContract):
    """Only the Accreditation Entity fixed at deployment time can change this registry."""

    name = "AccreditationRegistry"
    ROLES = frozenset({"Issuer", "Verifier"})

    def __init__(self, ledger: Ledger, authority_did: str, authority_key: rsa.RSAPublicKey) -> None:
        if did_from_public_key(authority_key) != authority_did:
            raise ValueError("authority DID does not match the authority key")
        self._authority_did = authority_did
        self._authority_key = authority_key
        self._entries: dict[str, dict[str, Any]] = {}
        super().__init__(ledger)

    @property
    def authority_did(self) -> str:
        return self._authority_did

    def _require_authority(self, tx: Transaction, method: str) -> None:
        if tx.sender != self._authority_did:
            raise UnauthorizedTransactionError("only the Accreditation Entity can call " + method)
        self._authorise(tx, method, self._authority_key)

    # -- transactions -------------------------------------------------------

    def accredit(self, tx: Transaction) -> None:
        self._require_authority(tx, "accredit")
        document, role = tx.params["didDocument"], tx.params["role"]
        if role not in self.ROLES:
            raise ValueError(f"role must be one of {sorted(self.ROLES)}")
        try:
            check_did_key_binding(document)
        except DIDResolutionError as exc:
            raise ValueError(str(exc)) from exc
        did = document["id"]
        if did in self._entries:
            raise ValueError(f"{did} is already registered")
        self._entries[did] = {
            "role": role,
            "status": ACCREDITED,
            "didDocument": copy.deepcopy(document),
            "updatedAt": format_timestamp(utc_now()),
        }
        self._emit("EntityAccredited", tx)

    def revoke(self, tx: Transaction) -> None:
        self._require_authority(tx, "revoke")
        entry = self._entries.get(tx.params["did"])
        if entry is None:
            raise ValueError("unknown DID")
        if entry["status"] == REVOKED:
            raise ValueError("accreditation already revoked")
        entry["status"] = REVOKED
        entry["updatedAt"] = format_timestamp(utc_now())
        self._emit("AccreditationRevoked", tx)

    # -- views --------------------------------------------------------------

    def get_did_document(self, did: str) -> dict[str, Any] | None:
        entry = self._entries.get(did)
        return copy.deepcopy(entry["didDocument"]) if entry else None

    def get_record(self, did: str) -> dict[str, Any] | None:
        entry = self._entries.get(did)
        if entry is None:
            return None
        return {
            "did": did,
            "role": entry["role"],
            "status": entry["status"],
            "publicKeyPem": public_key_to_pem(public_key_from_did_document(entry["didDocument"])),
        }

    def is_accredited(self, did: str, role: str) -> bool:
        entry = self._entries.get(did)
        return entry is not None and entry["status"] == ACCREDITED and entry["role"] == role
