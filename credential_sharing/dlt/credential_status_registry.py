"""CredentialStatusRegistry: public, issuer-controlled revocation of credentials.

Only an identifier of each credential (its salted Merkle root) is stored on
chain, never its content, so the registry leaks nothing about the student.
"""

from __future__ import annotations

from typing import Any

from credential_sharing.dlt.accreditation_registry import AccreditationRegistry
from credential_sharing.dlt.ledger import Ledger, SmartContract, Transaction
from credential_sharing.encoding import format_timestamp, utc_now
from credential_sharing.errors import UnauthorizedTransactionError
from credential_sharing.identity.did import public_key_from_did_document

VALID = "Valid"
REVOKED = "Revoked"


class CredentialStatusRegistry(SmartContract):
    name = "CredentialStatusRegistry"

    def __init__(self, ledger: Ledger, accreditation_registry: AccreditationRegistry) -> None:
        self._accreditations = accreditation_registry
        self._entries: dict[str, dict[str, Any]] = {}
        super().__init__(ledger)

    def _issuer_key(self, did: str):
        document = self._accreditations.get_did_document(did)
        if document is None:
            raise UnauthorizedTransactionError("sender is not a registered institution")
        return public_key_from_did_document(document)

    def register(self, tx: Transaction) -> None:
        if not self._accreditations.is_accredited(tx.sender, "Issuer"):
            raise UnauthorizedTransactionError("only accredited issuers can register credentials")
        self._authorise(tx, "register", self._issuer_key(tx.sender))
        status_id = tx.params["statusId"]
        if not isinstance(status_id, str) or not status_id:
            raise ValueError("invalid status identifier")
        if status_id in self._entries:
            raise ValueError("credential already registered")
        self._entries[status_id] = {
            "issuer": tx.sender,
            "status": VALID,
            "updatedAt": format_timestamp(utc_now()),
        }
        self._emit("CredentialRegistered", tx)

    def revoke(self, tx: Transaction) -> None:
        entry = self._entries.get(tx.params["statusId"])
        if entry is None:
            raise ValueError("unknown credential")
        if entry["issuer"] != tx.sender:
            raise UnauthorizedTransactionError("only the issuer of a credential can revoke it")
        # An issuer whose accreditation was withdrawn can still revoke what it issued.
        self._authorise(tx, "revoke", self._issuer_key(tx.sender))
        if entry["status"] == REVOKED:
            raise ValueError("credential already revoked")
        entry["status"] = REVOKED
        entry["updatedAt"] = format_timestamp(utc_now())
        self._emit("CredentialRevoked", tx)

    def get_status(self, status_id: str) -> dict[str, Any] | None:
        entry = self._entries.get(status_id)
        return dict(entry) if entry else None
