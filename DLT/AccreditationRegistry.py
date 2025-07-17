import time

class AccreditationRegistry:
    def __init__(self, accrediting_authority_did):
        self.accrediting_authority_did = accrediting_authority_did
        self.accredited_entities = {}  # Map DID -> metadata (tipo, timestamp, ecc.)

    def accredit_entity(self, caller_did, target_did, entity_type):
        # Controllo se il chiamante è l'ente di accreditamento (controllo fatto sul did)
        if caller_did != self.accrediting_authority_did:
            print(f"[AccreditationRegistry] ERRORE: {caller_did} non è autorizzato ad accreditare.")
            return False

        # Controllo se il did document esiste già nel dlt
        if target_did in self.accredited_entities:
            print(f"[AccreditationRegistry] DID già accreditato: {target_did}")
            return False

        if entity_type not in ["issuer", "verifier"]:
            return False

        self.accredited_entities[target_did] = {
            "type": entity_type,
            "timestamp": time.time()
        }
        print(f"[AccreditationRegistry] {entity_type} accreditato con DID: {target_did}")
        return True

    def is_accredited(self, did):
        return did in self.accredited_entities

    def list_accredited(self):
        return list(self.accredited_entities.keys())
