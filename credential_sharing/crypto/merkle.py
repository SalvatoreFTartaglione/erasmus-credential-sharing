"""Merkle tree with domain separation, used for selective disclosure.

Design choices (each one fixes a weakness of the first implementation):

* **Domain separation** - leaves are hashed as ``H(0x00 || data)`` and internal
  nodes as ``H(0x01 || left || right)`` (as in RFC 6962), so an internal node
  can never be passed off as a leaf (second-preimage attack).
* **No duplication of the last node** - an unpaired node is promoted unchanged
  to the next level instead of being hashed with itself, which avoids the
  ambiguity behind CVE-2012-2459 (two different leaf lists with the same root).
* Salting of the leaves is the caller's responsibility: see
  :func:`credential_sharing.credential.claim_leaf_hash`.

A proof is a list of compact steps ``"L<b64url hash>"`` / ``"R<b64url hash>"``
(sibling on the left/right), which keeps presentations small.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence

from credential_sharing.encoding import b64url_decode, b64url_encode

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
MAX_PROOF_LENGTH = 64

ProofStep = str  # "L<b64url sibling hash>" or "R<b64url sibling hash>"


def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


class MerkleTree:
    """Binary Merkle tree built over already-hashed leaves (see :func:`hash_leaf`)."""

    def __init__(self, leaf_hashes: Sequence[bytes]) -> None:
        if not leaf_hashes:
            raise ValueError("a Merkle tree needs at least one leaf")
        self._levels: list[list[bytes]] = [list(leaf_hashes)]
        while len(self._levels[-1]) > 1:
            level = self._levels[-1]
            parents = [hash_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
            if len(level) % 2:
                parents.append(level[-1])  # promote the unpaired node
            self._levels.append(parents)

    def __len__(self) -> int:
        return len(self._levels[0])

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    def proof(self, index: int) -> list[ProofStep]:
        """Audit path proving that leaf ``index`` belongs to the tree."""
        if not 0 <= index < len(self):
            raise IndexError(f"leaf index {index} out of range")
        steps: list[ProofStep] = []
        for level in self._levels[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                side = "L" if sibling < index else "R"
                steps.append(side + b64url_encode(level[sibling]))
            index //= 2
        return steps


def compute_root(leaf_hash: bytes, proof: Sequence[ProofStep]) -> bytes:
    if len(proof) > MAX_PROOF_LENGTH:
        raise ValueError("Merkle proof is too long")
    node = leaf_hash
    for step in proof:
        side, sibling = step[:1], b64url_decode(step[1:])
        if len(sibling) != hashlib.sha256().digest_size:
            raise ValueError("invalid sibling hash length")
        if side == "L":
            node = hash_node(sibling, node)
        elif side == "R":
            node = hash_node(node, sibling)
        else:
            raise ValueError(f"invalid proof step {step!r}")
    return node


def verify_proof(leaf_hash: bytes, proof: Sequence[ProofStep], root: bytes) -> bool:
    """Return ``True`` if ``proof`` links ``leaf_hash`` to ``root``. Never raises on bad input."""
    try:
        return hmac.compare_digest(compute_root(leaf_hash, proof), root)
    except (KeyError, TypeError, ValueError):
        return False
