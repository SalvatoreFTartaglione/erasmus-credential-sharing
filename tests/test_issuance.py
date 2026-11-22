import copy

import pytest

from credential_sharing.actors.issuer import Issuer
from credential_sharing.auth import PasswordHasher
from credential_sharing.credential import credential_signing_input
from credential_sharing.crypto.secure_channel import seal
from credential_sharing.encoding import b64url_encode, canonical_json
from credential_sharing.errors import AuthenticationError, VerificationError, WalletLockedError
from credential_sharing.identity.did import public_key_from_did_document
from credential_sharing.sample_data import DEMO_STUDENT_PASSWORD, DEMO_WALLET_PASSPHRASE
from credential_sharing.scenario import sample_record


def test_password_hashing():
    encoded = PasswordHasher.hash("s3cret")
    assert encoded.startswith("scrypt$") and "s3cret" not in encoded
    assert PasswordHasher.verify("s3cret", encoded)
    assert not PasswordHasher.verify("S3cret", encoded)
    assert PasswordHasher.hash("s3cret") != encoded  # random salt


def test_honest_issuance(system, holder):
    credential = holder.wallet.credentials[0]
    assert credential["credentialSubject"]["id"] == holder.did
    assert credential["issuanceDate"].endswith("Z") and "+00:00" not in credential["issuanceDate"]
    status = system.status_registry.get_status(credential["credentialStatus"]["statusId"])
    assert status == {"issuer": system.issuer.did, "status": "Valid", "updatedAt": status["updatedAt"]}


def test_wrong_password_is_rejected(system, student):
    with pytest.raises(AuthenticationError):
        system.issuer.begin_login(student.email, "wrong")
    assert not system.mailbox.messages  # no OTP sent


def test_wrong_otp_triggers_backoff_and_lockout(system, student, clock):
    issuer = system.issuer
    issuer.begin_login(student.email, DEMO_STUDENT_PASSWORD)
    for attempt in range(5):
        with pytest.raises(AuthenticationError):
            issuer.complete_login(student.email, "000000" if attempt else "not-an-otp")
        assert issuer.retry_after(student.email) == 2 ** attempt
        with pytest.raises(AuthenticationError, match=r"retry|locked"):
            issuer.complete_login(student.email, system.mailbox.last_code(student.email))
        clock.advance(2 ** attempt)
    with pytest.raises(AuthenticationError, match="locked"):
        issuer.complete_login(student.email, system.mailbox.last_code(student.email))


def test_otp_expires_and_is_single_use(system, student, clock):
    issuer = system.issuer
    issuer.begin_login(student.email, DEMO_STUDENT_PASSWORD)
    clock.advance(121)
    with pytest.raises(AuthenticationError):
        issuer.complete_login(student.email, system.mailbox.last_code(student.email))
    clock.advance(1)
    issuer.begin_login(student.email, DEMO_STUDENT_PASSWORD)
    code = system.mailbox.last_code(student.email)
    issuer.complete_login(student.email, code)
    with pytest.raises(AuthenticationError):
        issuer.complete_login(student.email, code)


def _login(system, student):
    system.issuer.begin_login(student.email, DEMO_STUDENT_PASSWORD)
    return system.issuer.complete_login(student.email, system.mailbox.last_code(student.email))


def test_credential_requires_a_bound_did(system, student):
    with pytest.raises(AuthenticationError, match="bind a DID"):
        system.issuer.issue_credential(_login(system, student))


def test_student_cannot_bind_someone_elses_did(system, student, other_student):
    """Without the victim's private key the DID binding proof fails."""
    token = _login(system, student)
    nonce = system.issuer.start_did_binding(token)
    signature = student.wallet.sign_did_binding(system.issuer.did, nonce)
    with pytest.raises(AuthenticationError, match="proof of possession"):
        system.issuer.bind_holder_did(token, other_student.did, signature)


def test_wallet_is_encrypted_at_rest(system):
    wallet = system.new_student(sample_record()).wallet
    wallet.lock()
    assert b"PRIVATE KEY" not in wallet._vault
    with pytest.raises(WalletLockedError):
        _ = wallet.credentials
    with pytest.raises(AuthenticationError):
        wallet.unlock("wrong passphrase")
    wallet.unlock(DEMO_WALLET_PASSPHRASE)
    assert wallet.credentials == []


def _resend(system, holder, credential):
    """Deliver ``credential`` to the holder as if it came from the issuer."""
    message = seal(canonical_json(credential), sender=credential["issuer"]["id"], recipient=holder.did,
                   recipient_public_key=public_key_from_did_document(holder.wallet.did_document))
    return holder.wallet.accept_credential(message)


@pytest.mark.parametrize("mutation", ["grade", "expiration", "subject"])
def test_wallet_rejects_altered_credentials(system, holder, mutation):
    credential = copy.deepcopy(holder.wallet.credentials[0])
    if mutation == "grade":
        credential["credentialSubject"]["learningAgreement"]["agreedCourses"][2]["grade"] = "30/30"
    elif mutation == "expiration":
        credential["expirationDate"] = "2099-01-01T00:00:00Z"
    else:
        credential["credentialSubject"]["id"] = "did:erasmus:someone-else"
    with pytest.raises(VerificationError):
        _resend(system, holder, credential)


def test_wallet_rejects_credentials_from_a_non_accredited_issuer(system, holder):
    rogue = Issuer("Rogue University", status_registry=system.status_registry,
                   student_registry=system.student_registry, otp_delivery=system.mailbox.deliver)
    credential = copy.deepcopy(holder.wallet.credentials[0])
    credential["issuer"] = {"id": rogue.did, "name": rogue.name}
    credential["proof"]["verificationMethod"] = f"{rogue.did}#keys-1"
    credential["proof"]["signatureValue"] = b64url_encode(rogue._keys.sign(credential_signing_input(credential)))
    with pytest.raises(VerificationError, match="not registered"):
        _resend(system, holder, credential)


def test_unrecognised_institution_is_not_accredited(system):
    rogue = Issuer("Rogue University", status_registry=system.status_registry,
                   student_registry=system.student_registry, otp_delivery=system.mailbox.deliver)
    with pytest.raises(AuthenticationError, match="not a recognised institution"):
        rogue.request_accreditation(system.authority)
    assert system.authority.registry.get_record(rogue.did) is None
