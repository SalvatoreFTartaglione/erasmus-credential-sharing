# Security review of version 1

This document records the review of the first implementation, which was submitted as course work (commit `c65fe35`). For each finding it gives the impact and the fix that version 2 applies. Findings marked **PoC** were confirmed by a working exploit. Every one of those exploits is now a regression test in `tests/`.

## Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Critical | Selective disclosure was not verified, so disclosed attributes could be forged (**PoC**) | Fixed |
| 2 | Critical | No holder binding, so a stolen credential was accepted (**PoC**) | Fixed |
| 3 | High | Challenge-response was simulated, so presentations could be replayed (**PoC**) | Fixed |
| 4 | High | Unsalted Merkle leaves leaked undisclosed attributes (**PoC**) | Fixed |
| 5 | High | The issuer signature did not cover the credential metadata | Fixed |
| 6 | Medium | The smart contracts had no access control (**PoC**) | Fixed |
| 7 | Medium | The verifier did not check the issuer's role or its accreditation status | Fixed |
| 8 | Medium | The wallet's accreditation check was ineffective, and X.509 validation was partial (**PoC**) | Fixed |
| 9 | Medium | The secure channel used AES-CBC without integrity, and the peer key was not authenticated | Fixed |
| 10 | Low | Weak handling of student authentication data | Fixed |
| 11 | Low | The wallet was not encrypted at rest, although the design required it | Fixed |

## Findings

### 1. Disclosed attributes could be forged (Critical)

The issuer signed a Merkle root computed over the top-level keys of `credentialSubject`. The wallet then built a *different* tree, over the courses only, to generate the proofs, and attached the original root to them. The verifier checked the issuer signature on that root and then skipped the proof verification entirely: it printed `"(Simulato)"`. A student could edit any grade, or add exams they never took, and the presentation was accepted.

**Fix.** Issuer and wallet now build the same tree over the same claims (`extract_claims`). The verifier recomputes every disclosed leaf and checks its proof against the signed root (step 7.B). Tests: `test_forged_grade_is_rejected`, `test_invented_exam_is_rejected`.

### 2. No holder binding (Critical)

The verifier checked the VP signature with the key of the DID in `holder`, but never compared `holder` with the credential subject. Anyone could take somebody else's credential and present it, signing with their own key.

**Fix.** Step 7.A rejects any presentation whose holder is not the credential subject, and the subject DID is part of the issuer-signed payload. Test: `test_stolen_credential_is_rejected`.

### 3. Replayable presentations (High)

The challenge-response step generated a nonce and returned `True` without involving the student. The VP contained no nonce and no audience, so a captured VP could be resubmitted indefinitely. Yet the report relied on this step to satisfy property C.4.

**Fix.** The verifier issues a single-use challenge with a TTL and its own DID as `domain`. Both values are covered by the holder signature, and the verifier consumes the challenge on use (step 7.E). Tests: `test_replayed_presentation_is_rejected`, `test_expired_challenge_is_rejected`, `test_presentation_for_another_verifier_is_rejected`.

### 4. Undisclosed attributes could be brute-forced (High)

A leaf was the hash of `{id, title, grade}` with no salt. A Merkle proof contains the leaves of neighbouring, undisclosed courses, and grades have very few possible values, so the verifier could recompute those leaves and learn the hidden results. For example, disclosing course 1 revealed "Automation, 30/30". In addition, leaves and internal nodes shared the same hash function, and the last node was duplicated (the CVE-2012-2459 pattern).

**Fix.** Each claim now has a 128-bit random salt. Leaf and node hashes use different prefixes, and an unpaired node is promoted instead of duplicated. Tests: `test_hidden_claims_cannot_be_brute_forced_from_proofs` and `tests/test_merkle.py`.

### 5. Metadata not covered by the issuer signature (High)

Only the root of `credentialSubject` was signed. `id`, `issuer`, `issuanceDate`, `expirationDate` and `credentialStatus` could be changed freely, and the expiration date was never checked.

**Fix.** `credential_signing_input` covers all of these fields plus the holder DID, and both wallet and verifier check the validity period. Tests: `test_altered_signed_metadata_is_rejected`, `test_expired_credential_is_rejected`, `test_wallet_rejects_altered_credentials`.

### 6. Smart contracts without access control (Medium)

`AccreditationRegistry.set_accrediting_authority` could be called by anyone, at any time. The "caller" of a contract was just a string with no signature. `CredentialStatusRegistry.register_credential` accepted any caller, accredited or not.

**Fix.** Every state-changing call is now a `Transaction` signed by its sender and protected by a per-sender nonce. The authority is fixed when the registry is deployed. Only accredited issuers can register credentials, and only the original issuer can revoke one. Students self-register their DIDs, with proof of possession. Tests: `tests/test_ledger_and_contracts.py`.

### 7. Issuer role and accreditation status not checked (Medium)

The verifier resolved the issuer as a "Verifier" and accepted any entity in the accreditation registry. An institution accredited only as a verifier could therefore issue credentials that would be accepted. Accreditation could not be revoked.

**Fix.** `require_accredited` checks the role, the status (`Accredited` or `Revoked`) and the X.509 chain. The AE can revoke accreditations. Tests: `test_issuer_with_revoked_accreditation_is_rejected`, `test_non_accredited_party_cannot_register_credentials`, `test_wallet_refuses_to_send_to_a_non_accredited_verifier`.

### 8. Ineffective wallet checks and partial X.509 validation (Medium)

`get_accreditation_status` always returned a non-empty dictionary, even for an unknown DID, so the wallet's `if not status` check never failed. Certificate validation verified only the signature and the dates. The student's revocation check sat after a `return True`, so it never ran.

**Fix.** Certificate validation now checks the issuer name, the signature, the validity window, that the certificate is not a CA, and that the CN, the OU and the public key match the ledger. The wallet runs the full set of checks, revocation included. Tests: `tests/test_crypto_primitives.py`, `tests/test_issuance.py`.

### 9. Unauthenticated encryption in the channel model (Medium)

The simulated TLS layer used AES-CBC with no MAC, which is malleable, and it stripped the padding without validating it. The verifier's public key was taken from the object itself rather than from the ledger.

**Fix.** The channel now uses AES-256-GCM, with the sender and recipient DIDs as associated data. The wallet obtains the recipient key from the ledger and validates it through the recipient's certificate, after checking the recipient's role. Tests: `test_secure_channel_*`, `test_tampered_ciphertext_is_rejected`.

### 10. Student authentication data (Low)

Demo passwords were written in clear text to `Student_Credentials/` and committed to the repository. Passwords and OTPs came from `random` and were compared in clear. The issuer discarded the student's public key and filled every credential with hard-coded personal data that belonged to a real person. The student's name was stored on chain inside the DID Document.

**Fix.** Passwords are now stored as scrypt hashes, OTPs come from `secrets`, are single-use and expire in 120 s, and failed attempts trigger exponential back-off and lock-out. The DID is bound to the student's account through proof of possession. Credentials are built from the student's enrolment record, the sample data is fictional, and DID Documents on chain contain no personal data.

### 11. Wallet not encrypted at rest (Low)

The report states that the wallet protects its data with AES-256, but private keys were held as unencrypted PEM.

**Fix.** The wallet state is now encrypted with AES-256-GCM under a key derived from the passphrase with scrypt. Test: `test_wallet_is_encrypted_at_rest`.

## Other bugs fixed

- `AE.giveAccreditation` returned a bare `False` on one error path. Callers that unpacked a tuple then raised `TypeError`.
- Timestamps were formatted as `...+00:00Z`, which is not a valid `dateTime`.
- `_build_merkle_tree` modified the list passed to it.
- Sizes were measured with `sys.getsizeof`, which adds Python object overhead. The measured latency included cryptographic work together with console output and disk I/O.
- The wallet imported the test module, and the verifier carried state from one presentation to the next in an instance attribute.
- `StudentDIDRegistry` used Python's `hash()`, which is randomised per process and is not cryptographic.
- Malformed presentations crashed the verifier. They are now rejected with an explanation.
