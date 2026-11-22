"""StudentDIDRegistry: self-registration of students' DID Documents.

A student registers its own DID Document with a transaction signed by the key
the document publishes (proof of possession). Because DIDs are derived from
keys, nobody can register a document under somebody else's DID. Documents hold
only public keys: no personal data is ever written on chain.
"""

from __future__ import annotations

import copy
from typing import Any

from credential_sharing.dlt.ledger import Ledger, SmartContract, Transaction
from credential_sharing.errors import DIDResolutionError, UnauthorizedTransactionError
from credential_sharing.identity.did import check_did_key_binding, public_key_from_did_document


class StudentDIDRegistry(SmartContract):
    name = "StudentDIDRegistry"

    def __init__(self, ledger: Ledger) -> None:
        self._documents: dict[str, dict[str, Any]] = {}
        super().__init__(ledger)

    def register(self, tx: Transaction) -> None:
        document = tx.params["didDocument"]
        try:
            check_did_key_binding(document)
        except DIDResolutionError as exc:
            raise UnauthorizedTransactionError(str(exc)) from exc
        if tx.sender != document["id"]:
            raise UnauthorizedTransactionError("a DID Document can only be registered by its subject")
        self._authorise(tx, "register", public_key_from_did_document(document))
        if document["id"] in self._documents:
            raise ValueError("DID already registered")
        self._documents[document["id"]] = copy.deepcopy(document)
        self._emit("StudentDIDRegistered", tx)

    def get_did_document(self, did: str) -> dict[str, Any] | None:
        document = self._documents.get(did)
        return copy.deepcopy(document) if document else None
