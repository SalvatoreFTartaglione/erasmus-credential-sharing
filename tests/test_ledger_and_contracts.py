import pytest

from credential_sharing.crypto.keys import KeyPair
from credential_sharing.dlt.ledger import Transaction
from credential_sharing.errors import UnauthorizedTransactionError
from credential_sharing.identity.did import build_did_document, did_from_public_key


def test_ledger_hash_chain_detects_tampering(system):
    assert system.ledger.verify_chain()
    system.ledger._blocks[2]["payload"]["event"] = "Forged"
    assert not system.ledger.verify_chain()


def test_only_the_authority_can_accredit(system):
    mallory = KeyPair.generate()
    did = did_from_public_key(mallory.public_key)
    registry = system.authority.registry
    tx = Transaction(registry.name, "accredit",
                     {"didDocument": build_did_document(did, mallory.public_key), "role": "Issuer"},
                     sender=did).signed_by(mallory)
    with pytest.raises(UnauthorizedTransactionError):
        registry.accredit(tx)


def test_authority_identity_cannot_be_spoofed(system):
    """Claiming to be the AE without its key fails: sender is checked against the signature."""
    mallory = KeyPair.generate()
    did = did_from_public_key(mallory.public_key)
    registry = system.authority.registry
    tx = Transaction(registry.name, "accredit",
                     {"didDocument": build_did_document(did, mallory.public_key), "role": "Issuer"},
                     sender=registry.authority_did).signed_by(mallory)
    with pytest.raises(UnauthorizedTransactionError, match="signature"):
        registry.accredit(tx)
    assert not hasattr(registry, "set_accrediting_authority")


def test_transactions_cannot_be_replayed(system, holder):
    registry = system.status_registry
    issuer = system.issuer
    status_id = issuer.issued_credentials[0]["statusId"]
    tx = Transaction(registry.name, "revoke", {"statusId": status_id, "reason": "x"},
                     sender=issuer.did).signed_by(issuer._keys)
    registry.revoke(tx)
    with pytest.raises(UnauthorizedTransactionError, match="replayed"):
        registry.revoke(tx)


def test_non_accredited_party_cannot_register_credentials(system):
    verifier = system.verifier  # accredited, but as a Verifier
    registry = system.status_registry
    tx = Transaction(registry.name, "register", {"statusId": "abc"}, sender=verifier.did).signed_by(verifier._keys)
    with pytest.raises(UnauthorizedTransactionError, match="accredited issuers"):
        registry.register(tx)


def test_only_the_issuer_can_revoke_its_credentials(system, holder):
    status_id = system.issuer.issued_credentials[0]["statusId"]
    verifier = system.verifier
    registry = system.status_registry
    tx = Transaction(registry.name, "revoke", {"statusId": status_id, "reason": "x"},
                     sender=verifier.did).signed_by(verifier._keys)
    with pytest.raises(UnauthorizedTransactionError):
        registry.revoke(tx)
    assert registry.get_status(status_id)["status"] == "Valid"


def test_student_did_cannot_be_squatted(system, student):
    mallory = KeyPair.generate()
    registry = system.student_registry
    hijacked = build_did_document(student.did, mallory.public_key)
    tx = Transaction(registry.name, "register", {"didDocument": hijacked}, sender=student.did).signed_by(mallory)
    with pytest.raises(UnauthorizedTransactionError):
        registry.register(tx)


def test_student_did_document_holds_no_personal_data(system, student):
    document = system.student_registry.get_did_document(student.did)
    assert student.name not in str(document) and student.email not in str(document)
