"""Wiring of the whole system: ledger, contracts, actors and phase 1 (accreditation)."""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Any

from credential_sharing.actors.accreditation_entity import AccreditationEntity
from credential_sharing.actors.issuer import Issuer
from credential_sharing.actors.student import Student
from credential_sharing.actors.verifier import Verifier
from credential_sharing.actors.wallet import Wallet
from credential_sharing.auth import Clock, SimulatedMailbox
from credential_sharing.dlt.credential_status_registry import CredentialStatusRegistry
from credential_sharing.dlt.ledger import Ledger
from credential_sharing.dlt.student_did_registry import StudentDIDRegistry
from credential_sharing.identity.did import DIDResolver
from credential_sharing.sample_data import (
    AE_NAME,
    DEMO_STUDENT_PASSWORD,
    DEMO_WALLET_PASSPHRASE,
    ISSUER_NAME,
    SAMPLE_RECORD,
    VERIFIER_NAME,
)
from credential_sharing.verification import TrustContext


@dataclass
class System:
    ledger: Ledger
    authority: AccreditationEntity
    status_registry: CredentialStatusRegistry
    student_registry: StudentDIDRegistry
    trust: TrustContext
    mailbox: SimulatedMailbox
    issuer: Issuer
    verifier: Verifier

    def new_student(
        self,
        record: dict[str, Any],
        *,
        password: str = DEMO_STUDENT_PASSWORD,
        passphrase: str = DEMO_WALLET_PASSPHRASE,
    ) -> Student:
        """Create a wallet, register its DID on chain and enrol the student at the issuer."""
        wallet = Wallet(passphrase, trust=self.trust)
        wallet.unlock(passphrase)
        wallet.register_did(self.student_registry)
        name = f"{record['givenName']} {record['familyName']}"
        self.issuer.enroll_student(record["email"], password, record)
        return Student(name, record["email"], wallet)

    def otp_reader(self, student: Student):
        """OTP 'typed in' by the student, read from the simulated mailbox."""
        return lambda: self.mailbox.last_code(student.email)


def build_system(*, clock: Clock = time.monotonic) -> System:
    """Deploy the contracts and run phase 1 (accreditation of issuer and verifier)."""
    ledger = Ledger()
    authority = AccreditationEntity(AE_NAME, ledger, recognised_institutions={ISSUER_NAME, VERIFIER_NAME})
    status_registry = CredentialStatusRegistry(ledger, authority.registry)
    student_registry = StudentDIDRegistry(ledger)
    trust = TrustContext(
        resolver=DIDResolver(authority.registry, student_registry),
        accreditation_registry=authority.registry,
        status_registry=status_registry,
        trust_anchor=authority.ca_certificate,
    )
    mailbox = SimulatedMailbox()
    issuer = Issuer(
        ISSUER_NAME,
        status_registry=status_registry,
        student_registry=student_registry,
        otp_delivery=mailbox.deliver,
        clock=clock,
    )
    verifier = Verifier(VERIFIER_NAME, trust=trust, clock=clock)
    issuer.request_accreditation(authority)
    verifier.request_accreditation(authority)
    return System(ledger, authority, status_registry, student_registry, trust, mailbox, issuer, verifier)


def sample_record() -> dict[str, Any]:
    return copy.deepcopy(SAMPLE_RECORD)
