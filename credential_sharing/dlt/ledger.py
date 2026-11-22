"""A hash-chained ledger and a minimal smart-contract runtime.

Consensus and networking are out of scope: the ledger is a single append-only
list of blocks, each one committing to the previous block's hash. What *is*
modelled faithfully is authorisation: every state-changing call is a
:class:`Transaction` signed by its sender, and contracts check the signature,
the sender's rights and a per-sender nonce (replay protection) before
mutating state, like ``msg.sender`` checks in an EVM contract. Read-only
"view" calls are free and unauthenticated.
"""

from __future__ import annotations

import copy
import hashlib
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar

from cryptography.hazmat.primitives.asymmetric import rsa

from credential_sharing.crypto.keys import KeyPair, verify_signature
from credential_sharing.encoding import (
    b64url_decode,
    b64url_encode,
    canonical_json,
    format_timestamp,
    utc_now,
)
from credential_sharing.errors import UnauthorizedTransactionError

GENESIS_HASH = "0" * 64


@dataclass
class Transaction:
    contract: str
    method: str
    params: dict[str, Any]
    sender: str
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    signature: str = ""

    def signing_payload(self) -> bytes:
        return canonical_json(
            {
                "contract": self.contract,
                "method": self.method,
                "params": self.params,
                "sender": self.sender,
                "nonce": self.nonce,
            }
        )

    def signed_by(self, keys: KeyPair) -> Transaction:
        self.signature = b64url_encode(keys.sign(self.signing_payload()))
        return self

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(asdict(self))


class Ledger:
    """Append-only list of hash-chained blocks."""

    def __init__(self) -> None:
        self._blocks: list[dict[str, Any]] = []

    def __len__(self) -> int:
        return len(self._blocks)

    @property
    def blocks(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._blocks)

    @staticmethod
    def _hash(block: dict[str, Any]) -> str:
        body = {key: value for key, value in block.items() if key != "hash"}
        return hashlib.sha256(canonical_json(body)).hexdigest()

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        block = {
            "index": len(self._blocks),
            "timestamp": format_timestamp(utc_now()),
            "previousHash": self._blocks[-1]["hash"] if self._blocks else GENESIS_HASH,
            "payload": copy.deepcopy(payload),
        }
        block["hash"] = self._hash(block)
        self._blocks.append(block)
        return copy.deepcopy(block)

    def verify_chain(self) -> bool:
        """Recompute every hash and link; ``False`` if any block was altered."""
        previous = GENESIS_HASH
        for index, block in enumerate(self._blocks):
            if block["index"] != index or block["previousHash"] != previous:
                return False
            if block["hash"] != self._hash(block):
                return False
            previous = block["hash"]
        return True


class SmartContract:
    """Base class giving contracts signature checks, replay protection and event logging."""

    name: ClassVar[str]

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._used_nonces: set[tuple[str, str]] = set()
        ledger.append({"event": "ContractDeployed", "contract": self.name})

    def _authorise(self, tx: Transaction, method: str, sender_key: rsa.RSAPublicKey) -> None:
        if tx.contract != self.name or tx.method != method:
            raise UnauthorizedTransactionError("transaction targets a different contract method")
        if (tx.sender, tx.nonce) in self._used_nonces:
            raise UnauthorizedTransactionError("replayed transaction (nonce already used)")
        try:
            signature = b64url_decode(tx.signature)
        except ValueError as exc:
            raise UnauthorizedTransactionError("malformed transaction signature") from exc
        if not verify_signature(sender_key, tx.signing_payload(), signature):
            raise UnauthorizedTransactionError("invalid transaction signature")
        self._used_nonces.add((tx.sender, tx.nonce))

    def _emit(self, event: str, tx: Transaction) -> None:
        self._ledger.append({"event": event, "contract": self.name, "transaction": tx.to_dict()})
