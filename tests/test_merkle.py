import hashlib

import pytest

from credential_sharing.crypto.merkle import MerkleTree, hash_leaf, hash_node, verify_proof


def leaves(count: int) -> list[bytes]:
    return [hash_leaf(f"leaf-{i}".encode()) for i in range(count)]


@pytest.mark.parametrize("count", range(1, 18))
def test_every_leaf_has_a_valid_proof(count):
    tree = MerkleTree(leaves(count))
    for index, leaf in enumerate(leaves(count)):
        assert verify_proof(leaf, tree.proof(index), tree.root)


def test_proof_rejects_a_different_leaf():
    tree = MerkleTree(leaves(5))
    assert not verify_proof(hash_leaf(b"forged"), tree.proof(0), tree.root)


def test_proof_rejects_a_tampered_sibling():
    tree = MerkleTree(leaves(4))
    proof = tree.proof(1)
    proof[0] = proof[0][0] + "A" * 43
    assert not verify_proof(leaves(4)[1], proof, tree.root)


def test_leaf_and_node_hashes_are_domain_separated():
    left, right = leaves(2)
    tree = MerkleTree([left, right])
    # An internal node presented as a leaf must not verify (second-preimage attack).
    assert tree.root == hash_node(left, right)
    assert not verify_proof(hash_leaf(left + right), [], tree.root)
    assert hash_leaf(b"x") != hashlib.sha256(b"x").digest()


def test_odd_leaf_is_promoted_not_duplicated():
    # With duplication, [a, b, c] and [a, b, c, c] would share the same root (CVE-2012-2459).
    a, b, c = leaves(3)
    assert MerkleTree([a, b, c]).root != MerkleTree([a, b, c, c]).root


@pytest.mark.parametrize("bad_proof", [
    ["X" + "A" * 43],
    ["L" + "A" * 10],
    ["L"],
    [""],
    [{"position": "left"}],
    ["L" + "A" * 43] * 100,
])
def test_malformed_proofs_are_rejected_without_raising(bad_proof):
    tree = MerkleTree(leaves(2))
    assert not verify_proof(leaves(2)[0], bad_proof, tree.root)


def test_empty_tree_is_refused():
    with pytest.raises(ValueError):
        MerkleTree([])
