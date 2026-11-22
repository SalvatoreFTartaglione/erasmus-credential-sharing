"""Command-line interface: an interactive wallet and a scripted end-to-end demo."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import time
from collections.abc import Callable
from typing import Any

from credential_sharing import adversary
from credential_sharing.actors.student import Student
from credential_sharing.actors.verifier import VerificationReport
from credential_sharing.errors import AuthenticationError, CredentialSharingError
from credential_sharing.sample_data import DEMO_STUDENT_PASSWORD, DEMO_WALLET_PASSPHRASE
from credential_sharing.scenario import System, build_system, sample_record

COURSE_1 = "learningAgreement.agreedCourses.1"
COURSE_2 = "learningAgreement.agreedCourses.2"


# -- presentation helpers ------------------------------------------------------


def banner(title: str) -> None:
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


def describe_claim(name: str, value: Any) -> str:
    if isinstance(value, dict) and "title" in value:
        grade = f", grade {value['grade']}" if value.get("grade") else ""
        return f"{value['title']} ({value['ects']} ECTS): {value['status']}{grade}"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def print_report(report: VerificationReport) -> None:
    for step in report.steps:
        mark = " OK " if step.passed else "FAIL"
        print(f"  [{mark}] {step.step:<4} {step.title}: {step.detail}")
    if report.valid:
        print("  => presentation ACCEPTED. Claims processed by the verifier:")
        for name, value in report.accepted_claims.items():
            print(f"       - {describe_claim(name, value)}")
    else:
        print("  => presentation REJECTED")


def parse_selection(text: str, upper: int) -> list[int]:
    """Parse ``"1, 3;4"`` into ``[1, 3, 4]``; raise ``ValueError`` on bad input."""
    tokens = [token for token in text.replace(";", ",").replace(" ", ",").split(",") if token]
    if not tokens:
        raise ValueError("empty selection")
    numbers = sorted({int(token) for token in tokens})
    if numbers[0] < 1 or numbers[-1] > upper:
        raise ValueError(f"choose numbers between 1 and {upper}")
    return numbers


# -- scripted demo -------------------------------------------------------------


def _attack(label: str, attempt: Callable[[], VerificationReport]) -> tuple[str, str]:
    print(f"\n--- {label}")
    report = attempt()
    print_report(report)
    failure = report.failure
    outcome = "ACCEPTED (vulnerable!)" if report.valid else f"rejected at {failure.step}: {failure.detail}"
    return label, outcome


def run_demo() -> int:
    banner("Phase 1 - Accreditation of issuer and verifier")
    system = build_system()
    issuer, verifier = system.issuer, system.verifier

    banner("Phase 2 - Authentication and credential issuance")
    student = system.new_student(sample_record())
    student.obtain_credential(issuer, DEMO_STUDENT_PASSWORD, system.otp_reader(student))

    banner("Phase 3 - Selective disclosure and verification")
    print("Università di Salerno asks for 'Data Science' and 'Automation' only.")
    requested = [COURSE_1, COURSE_2]
    start = time.perf_counter()
    report = student.present(verifier, requested, requested_claims=requested)
    elapsed = (time.perf_counter() - start) * 1000
    print_report(report)
    print(f"  (request, presentation, encryption and verification took {elapsed:.1f} ms)")

    banner("Threat model - simulated attacks (WP1)")
    wallet = student.wallet
    outcomes: list[tuple[str, str]] = []

    def presentation_for(claims: list[str]) -> tuple[dict, dict]:
        request = verifier.create_presentation_request(claims)
        return request, wallet.create_presentation(request, claims)

    def forged_grade() -> VerificationReport:
        _, presentation = presentation_for(requested)
        forged = adversary.forge_claim(presentation, wallet, COURSE_1, "grade", "30/30")
        return verifier.receive_presentation(wallet.send_presentation(forged, verifier.did))

    def invented_exam() -> VerificationReport:
        _, presentation = presentation_for(requested)
        fake = {"name": "learningAgreement.agreedCourses.99", "salt": "AAAA",
                "value": {"id": 99, "title": "Quantum Computing", "ects": 9, "status": "Passed",
                          "grade": "30/30", "honor": True, "language": "English"},
                "proof": []}
        forged = adversary.invent_claim(presentation, wallet, fake)
        return verifier.receive_presentation(wallet.send_presentation(forged, verifier.did))

    def replay() -> VerificationReport:
        _, presentation = presentation_for(requested)
        captured = wallet.send_presentation(presentation, verifier.did)
        verifier.receive_presentation(captured)  # the honest, accepted submission
        return verifier.receive_presentation(captured)  # the replay

    def stolen_credential() -> VerificationReport:
        other = sample_record() | {"givenName": "Aldo", "familyName": "Neri",
                                   "email": "aldo.neri@studenti.example.org"}
        attacker = system.new_student(other)
        _, victim_presentation = presentation_for(requested)
        request = verifier.create_presentation_request(requested)
        stolen = adversary.present_stolen_credential(victim_presentation, attacker.wallet, request)
        return verifier.receive_presentation(attacker.wallet.send_presentation(stolen, verifier.did))

    def tampered_in_transit() -> VerificationReport:
        _, presentation = presentation_for(requested)
        message = wallet.send_presentation(presentation, verifier.did)
        return verifier.receive_presentation(adversary.tamper_ciphertext(message))

    def revoked() -> VerificationReport:
        status_id = issuer.issued_credentials[0]["statusId"]
        issuer.revoke_credential(status_id, "administrative error")
        return student.present(verifier, requested, requested_claims=requested)

    outcomes.append(_attack("Malicious student raises a grade and re-signs", forged_grade))
    outcomes.append(_attack("Malicious student adds an exam never taken", invented_exam))
    outcomes.append(_attack("Eavesdropper/verifier replays a captured presentation", replay))
    outcomes.append(_attack("Impersonator presents a stolen credential", stolen_credential))
    outcomes.append(_attack("Man in the middle tampers with the encrypted VP", tampered_in_transit))
    outcomes.append(_attack("Presentation after the issuer revoked the credential", revoked))

    banner("Summary")
    for label, outcome in outcomes:
        print(f"  - {label:<55} {outcome}")
    print(f"\nLedger: {len(system.ledger)} blocks, hash chain valid: {system.ledger.verify_chain()}")
    return 0 if all("rejected" in outcome for _, outcome in outcomes) and report.valid else 1


# -- interactive wallet --------------------------------------------------------


def _request_credential(system: System, student: Student) -> None:
    issuer = system.issuer
    password = getpass.getpass(f"Password for {student.email} at {issuer.name}: ")
    try:
        issuer.begin_login(student.email, password)
    except AuthenticationError as exc:
        print(f"Login failed: {exc}")
        return
    print(f"[simulated inbox] one-time password: {system.mailbox.last_code(student.email)}")
    while True:
        try:
            token = issuer.complete_login(student.email, input("One-time password: ").strip())
            break
        except AuthenticationError as exc:
            print(f"Login failed: {exc}")
            if "locked" in str(exc):
                return
            wait = issuer.retry_after(student.email)
            if wait > 0:
                print(f"Waiting {wait:.0f} s before the next attempt (brute-force protection)...")
                time.sleep(wait)
    nonce = issuer.start_did_binding(token)
    issuer.bind_holder_did(token, student.did, student.wallet.sign_did_binding(issuer.did, nonce))
    student.wallet.accept_credential(issuer.issue_credential(token))
    print("Credential received, verified and stored in the wallet.")


def _present(system: System, student: Student) -> None:
    claims = student.wallet.disclosable_claims()
    for number, (name, value) in enumerate(claims, start=1):
        print(f"  [{number:>2}] {name:<45} {describe_claim(name, value)}")
    text = input("Claims to disclose (e.g. 8,9) or empty to cancel: ").strip()
    if not text:
        return
    try:
        chosen = [claims[number - 1][0] for number in parse_selection(text, len(claims))]
    except ValueError as exc:
        print(f"Invalid selection: {exc}")
        return
    start = time.perf_counter()
    report = student.present(system.verifier, chosen, requested_claims=chosen)
    print_report(report)
    print(f"  (completed in {(time.perf_counter() - start) * 1000:.1f} ms)")


def run_interactive() -> int:
    banner("Erasmus credential wallet")
    system = build_system()
    student = system.new_student(sample_record())
    student.wallet.lock()
    print(f"Student: {student.name} <{student.email}>  DID: {student.did}")
    print(f"Demo secrets - portal password: {DEMO_STUDENT_PASSWORD!r}, "
          f"wallet passphrase: {DEMO_WALLET_PASSPHRASE!r}")

    menu = {
        "1": "Unlock the wallet",
        "2": f"Request the credential from {system.issuer.name}",
        "3": "Show the credential claims",
        "4": f"Present claims to {system.verifier.name}",
        "5": f"Revoke the credential (acting as {system.issuer.name})",
        "6": "Show the ledger",
        "0": "Exit",
    }
    while True:
        print()
        for key, label in menu.items():
            print(f"  [{key}] {label}")
        choice = input("> ").strip()
        try:
            if choice == "0":
                return 0
            if choice == "1":
                student.wallet.unlock(getpass.getpass("Wallet passphrase: "))
                print("Wallet unlocked.")
            elif choice == "2":
                _request_credential(system, student)
            elif choice == "3":
                for name, value in student.wallet.disclosable_claims():
                    print(f"  {name:<45} {describe_claim(name, value)}")
            elif choice == "4":
                _present(system, student)
            elif choice == "5":
                issued = system.issuer.issued_credentials
                if not issued:
                    print("No credential issued yet.")
                else:
                    system.issuer.revoke_credential(issued[-1]["statusId"], "revoked from the CLI")
                    print("Credential revoked on the ledger.")
            elif choice == "6":
                for block in system.ledger.blocks:
                    payload = block["payload"]
                    tx = payload.get("transaction", {})
                    print(f"  #{block['index']:<3} {block['hash'][:16]}  {payload['event']:<22} "
                          f"{payload['contract']:<26} {tx.get('sender', '')}")
                print(f"  hash chain valid: {system.ledger.verify_chain()}")
            else:
                print("Unknown option.")
        except IndexError:
            print("The wallet holds no credential yet.")
        except CredentialSharingError as exc:
            print(f"Error: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="credential-sharing",
        description="Selective disclosure and revocation of academic credentials (Erasmus scenario).",
    )
    parser.add_argument("--demo", action="store_true",
                        help="run the whole scenario non-interactively, including simulated attacks")
    parser.add_argument("-q", "--quiet", action="store_true", help="hide the protocol trace")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.ERROR if args.quiet else logging.INFO, format="  | %(message)s")
    return run_demo() if args.demo else run_interactive()
