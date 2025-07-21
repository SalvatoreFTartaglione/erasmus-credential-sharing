import time
import json


class CredentialStatusRegistry:
    def __init__(self, dlt):
        self.credential_statuses = {}
        self.dlt = dlt
        


    def register_credential(self, credential_hash, issuer_did):
        if not credential_hash:
            print("[CredentialStatusRegistry] ERRORE: Hash credenziale non valido")
            return False

        if credential_hash in self.credential_statuses:
            print(f"[CredentialStatusRegistry] Credenziale già registrata: {credential_hash}")
            return False

        # la key = credential_hash è la merkle root
        self.credential_statuses[credential_hash] = {
            "status": "Valid",
            "issuer": issuer_did,
            "timestamp": time.time()
        }

        block_data = {
            "type": "CredentialRegistration",
            "credential_hash": credential_hash,
            "issuer": issuer_did,
            "status": "Valid",
            "timestamp": time.time()
        }

        self.dlt.add_block(block_data)
        print(f"[DLT] Credenziale registrata on-chain: {credential_hash}")
        return True

    def revoke_credential(self, credential_hash, issuer_did):
        if credential_hash not in self.credential_statuses:
            print(f"[CredentialStatusRegistry] Credenziale non trovata: {credential_hash}")
            return False

        record = self.credential_statuses[credential_hash]

        if record["issuer"] != issuer_did:
            print("[CredentialStatusRegistry] ERRORE: Solo l'issuer che ha registrato la credenziale può revocarla")
            return False

        if record["status"] == "Revoked":
            print("[CredentialStatusRegistry] Credenziale già revocata")
            return False

        self.credential_statuses[credential_hash]["status"] = "Revoked"

        block_data = {
            "type": "CredentialRevocation",
            "credential_hash": credential_hash,
            "issuer": issuer_did,
            "status": "Revoked",
            "timestamp": time.time()
        }

        self.dlt.add_block(block_data)
        print(f"[DLT] Credenziale revocata on-chain: {credential_hash}")
        return True

    def get_credential_status(self, credential_hash):
        return self.credential_statuses.get(credential_hash, None)

    def is_credential_valid(self, credential_hash):
        record = self.credential_statuses.get(credential_hash)
        return record is not None and record["status"] == "Valid"

    def list_credentials(self):
        return list(self.credential_statuses.keys())
