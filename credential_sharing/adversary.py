"""Attacks from the WP1 threat model, used by the demo and by the test-suite.

Each helper produces what an adversary with the capabilities listed in the
report could send; the verifier is expected to reject all of them.
"""

from __future__ import annotations

import copy
from typing import Any

from credential_sharing.actors.wallet import Wallet
from credential_sharing.crypto.secure_channel import SealedMessage


def forge_claim(
    presentation: dict[str, Any], wallet: Wallet, claim_name: str, field: str, new_value: Any
) -> dict[str, Any]:
    """Malicious student (Maurizio): edit a disclosed value and re-sign with his own key.

    He fully controls his wallet, so the holder signature will be valid: only
    the issuer-signed Merkle root can reveal the forgery.
    """
    forged = copy.deepcopy(presentation)
    for claim in forged["verifiableCredential"][0]["disclosedClaims"]:
        if claim["name"] == claim_name:
            claim["value"][field] = new_value
            break
    else:
        raise KeyError(claim_name)
    proof = forged["proof"]
    return wallet.sign_presentation(forged, challenge=proof["challenge"], domain=proof["domain"])


def invent_claim(presentation: dict[str, Any], wallet: Wallet, claim: dict[str, Any]) -> dict[str, Any]:
    """Malicious student: add a course that is not in the credential."""
    forged = copy.deepcopy(presentation)
    forged["verifiableCredential"][0]["disclosedClaims"].append(claim)
    proof = forged["proof"]
    return wallet.sign_presentation(forged, challenge=proof["challenge"], domain=proof["domain"])


def present_stolen_credential(
    victim_presentation: dict[str, Any], attacker: Wallet, request: dict[str, Any]
) -> dict[str, Any]:
    """Impersonator (Aldo): reuse a captured credential under his own DID."""
    stolen = copy.deepcopy(victim_presentation)
    stolen["holder"] = attacker.did
    return attacker.sign_presentation(stolen, challenge=request["challenge"], domain=request["domain"])


def tamper_ciphertext(message: SealedMessage) -> SealedMessage:
    """Man in the middle (Candido): flip one bit of the encrypted presentation."""
    corrupted = bytearray(message.ciphertext)
    corrupted[len(corrupted) // 2] ^= 0x01
    return SealedMessage(message.sender, message.recipient, message.wrapped_key, message.nonce, bytes(corrupted))
