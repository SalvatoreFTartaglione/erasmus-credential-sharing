"""End-to-end verification, including every attack of the WP1 threat model.

The first group of tests reproduces the proof-of-concept attacks that the
original implementation accepted; all of them must now be rejected.
"""

import copy
import datetime as dt
import json

import pytest

from credential_sharing import adversary
from credential_sharing.credential import claim_leaf_hash
from credential_sharing.encoding import b64url_encode
from credential_sharing.errors import VerificationError
from tests.conftest import COURSE_1, COURSE_2, COURSE_3


def present(system, holder, claims, requested=None):
    request = system.verifier.create_presentation_request(claims if requested is None else requested)
    return request, holder.wallet.create_presentation(request, claims)


def send(system, wallet, presentation):
    return system.verifier.receive_presentation(wallet.send_presentation(presentation, system.verifier.did))


def failed_step(report):
    assert not report.valid
    return report.failure.step


def test_honest_presentation_is_accepted(system, holder):
    report = holder.present(system.verifier, [COURSE_1, COURSE_2], requested_claims=[COURSE_1, COURSE_2])
    assert report.valid, report.failure
    assert [step.step for step in report.steps] == ["TLS", "7.A", "7.B", "7.C", "7.D", "7.E", "7.F"]
    assert report.accepted_claims[COURSE_1]["grade"] == "27/30"
    assert report.holder == holder.did and report.issuer == system.issuer.did


def test_presentation_reveals_only_selected_claims(system, holder):
    _, presentation = present(system, holder, [COURSE_1])
    text = json.dumps(presentation, ensure_ascii=False)
    for hidden in ("Automation", "Giulia", "Bianchi", "2001-04-12", "disclosureSalts", "Hackathon"):
        assert hidden not in text


def test_unrequested_claims_are_discarded(system, holder):
    report = holder.present(system.verifier, [COURSE_1, COURSE_2], requested_claims=[COURSE_1])
    assert report.valid
    assert list(report.accepted_claims) == [COURSE_1] and report.ignored_claims == [COURSE_2]


def test_missing_requested_claim_is_rejected(system, holder):
    _, presentation = present(system, holder, [COURSE_1], requested=[COURSE_1, COURSE_2])
    assert failed_step(send(system, holder.wallet, presentation)) == "7.F"


# -- attacks that the original implementation accepted ---------------------------


def test_forged_grade_is_rejected(system, holder):
    _, presentation = present(system, holder, [COURSE_3])
    forged = adversary.forge_claim(presentation, holder.wallet, COURSE_3, "grade", "30/30")
    assert failed_step(send(system, holder.wallet, forged)) == "7.B"


def test_invented_exam_is_rejected(system, holder):
    _, presentation = present(system, holder, [COURSE_1])
    fake = {"name": "learningAgreement.agreedCourses.99", "salt": "AAAA", "proof": [],
            "value": {"id": 99, "title": "Quantum Computing", "grade": "30/30"}}
    forged = adversary.invent_claim(presentation, holder.wallet, fake)
    assert failed_step(send(system, holder.wallet, forged)) == "7.B"


def test_stolen_credential_is_rejected(system, holder, other_student):
    _, victim_presentation = present(system, holder, [COURSE_1])
    request = system.verifier.create_presentation_request([COURSE_1])
    stolen = adversary.present_stolen_credential(victim_presentation, other_student.wallet, request)
    assert failed_step(send(system, other_student.wallet, stolen)) == "7.A"


def test_replayed_presentation_is_rejected(system, holder):
    _, presentation = present(system, holder, [COURSE_1])
    message = holder.wallet.send_presentation(presentation, system.verifier.did)
    assert system.verifier.receive_presentation(message).valid
    assert failed_step(system.verifier.receive_presentation(message)) == "7.E"


def test_hidden_claims_cannot_be_brute_forced_from_proofs(system, holder):
    """The Merkle sibling of a disclosed course is the leaf of a hidden one.

    Disclosing "Automation" puts the leaf of "Design and Analysis of Algorithms"
    (failed) in the proof. With unsalted leaves a verifier could recompute it for
    every possible status/grade and learn the hidden result; the per-claim salt
    makes this infeasible.
    """
    _, presentation = present(system, holder, [COURSE_2])
    siblings = {step[1:] for claim in presentation["verifiableCredential"][0]["disclosedClaims"]
                for step in claim["proof"]}
    credential = holder.wallet.credentials[0]
    hidden_value = dict(holder.wallet.disclosable_claims())[COURSE_3]
    real_salt = credential["disclosureSalts"][COURSE_3]
    assert b64url_encode(claim_leaf_hash(COURSE_3, real_salt, hidden_value)) in siblings  # sanity check

    for status in ("Passed", "Failed", "Not taken"):
        for grade in [None, "Pass"] + [f"{n}/30" for n in range(18, 31)]:
            guess = dict(hidden_value, status=status, grade=grade)
            for salt in ("", "AAAAAAAAAAAAAAAAAAAAAA"):
                assert b64url_encode(claim_leaf_hash(COURSE_3, salt, guess)) not in siblings


# -- further threat-model scenarios ----------------------------------------------


def test_tampered_ciphertext_is_rejected(system, holder):
    _, presentation = present(system, holder, [COURSE_1])
    message = adversary.tamper_ciphertext(holder.wallet.send_presentation(presentation, system.verifier.did))
    assert failed_step(system.verifier.receive_presentation(message)) == "TLS"


def test_presentation_for_another_verifier_is_rejected(system, holder):
    request = system.verifier.create_presentation_request([COURSE_1])
    presentation = holder.wallet.create_presentation(dict(request, domain="did:erasmus:other"), [COURSE_1])
    assert failed_step(system.verifier.verify_presentation(presentation)) == "7.E"


def test_expired_challenge_is_rejected(system, holder, clock):
    _, presentation = present(system, holder, [COURSE_1])
    clock.advance(301)
    assert failed_step(send(system, holder.wallet, presentation)) == "7.E"


def test_revoked_credential_is_rejected(system, holder):
    system.issuer.revoke_credential(system.issuer.issued_credentials[0]["statusId"], "fraud")
    _, presentation = present(system, holder, [COURSE_1])
    assert failed_step(send(system, holder.wallet, presentation)) == "7.D"


def test_expired_credential_is_rejected(system, holder):
    _, presentation = present(system, holder, [COURSE_1])
    report = system.verifier.verify_presentation(
        presentation, now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=4 * 365))
    assert failed_step(report) in {"7.C", "7.D"}  # certificate and credential both expired


def test_issuer_with_revoked_accreditation_is_rejected(system, holder):
    system.authority.revoke_accreditation(system.issuer.did, "audit failed")
    _, presentation = present(system, holder, [COURSE_1])
    assert failed_step(system.verifier.verify_presentation(presentation)) == "7.C"


def test_altered_signed_metadata_is_rejected(system, holder):
    _, presentation = present(system, holder, [COURSE_1])
    altered = copy.deepcopy(presentation)
    altered["verifiableCredential"][0]["expirationDate"] = "2099-01-01T00:00:00Z"
    resigned = holder.wallet.sign_presentation(altered, challenge=presentation["proof"]["challenge"],
                                               domain=presentation["proof"]["domain"])
    assert failed_step(send(system, holder.wallet, resigned)) == "7.B"


def test_presentation_signed_by_third_party_is_rejected(system, holder, other_student):
    request, presentation = present(system, holder, [COURSE_1])
    resigned = other_student.wallet.sign_presentation(presentation, challenge=request["challenge"],
                                                      domain=request["domain"])
    assert failed_step(system.verifier.verify_presentation(resigned)) == "7.A"


@pytest.mark.parametrize("garbage", [{}, {"type": ["VerifiablePresentation"]}, {"holder": 3}, []])
def test_malformed_presentations_are_rejected_gracefully(system, garbage):
    report = system.verifier.verify_presentation(garbage)
    assert not report.valid and report.failure.step == "7.A"


def test_wallet_refuses_to_send_to_a_non_accredited_verifier(system, holder):
    request = system.verifier.create_presentation_request([COURSE_1])
    presentation = holder.wallet.create_presentation(dict(request, domain=system.issuer.did), [COURSE_1])
    with pytest.raises(VerificationError, match="Issuer, not as Verifier"):
        holder.wallet.send_presentation(presentation, system.issuer.did)
