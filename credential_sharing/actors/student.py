"""Student (holder): drives the wallet through issuance and presentation."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any

from credential_sharing.actors.issuer import Issuer
from credential_sharing.actors.verifier import VerificationReport, Verifier
from credential_sharing.actors.wallet import Wallet

log = logging.getLogger(__name__)


class Student:
    def __init__(self, name: str, email: str, wallet: Wallet) -> None:
        self.name = name
        self.email = email
        self.wallet = wallet

    @property
    def did(self) -> str:
        return self.wallet.did

    def obtain_credential(self, issuer: Issuer, password: str, read_otp: Callable[[], str]) -> dict[str, Any]:
        """Phase 2: authenticate (password + OTP), bind the DID, receive and check the VC."""
        log.info("%s: logging in to the %s portal", self.name, issuer.name)
        issuer.begin_login(self.email, password)
        token = issuer.complete_login(self.email, read_otp())
        nonce = issuer.start_did_binding(token)
        issuer.bind_holder_did(token, self.did, self.wallet.sign_did_binding(issuer.did, nonce))
        return self.wallet.accept_credential(issuer.issue_credential(token))

    def present(
        self,
        verifier: Verifier,
        claim_names: Iterable[str],
        *,
        requested_claims: Iterable[str] = (),
    ) -> VerificationReport:
        """Phase 3: answer a presentation request disclosing only ``claim_names``."""
        request = verifier.create_presentation_request(requested_claims)
        presentation = self.wallet.create_presentation(request, claim_names)
        return verifier.receive_presentation(self.wallet.send_presentation(presentation, verifier.did))
