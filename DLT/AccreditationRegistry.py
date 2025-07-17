import time

class AccreditationRegistry:
    def __init__(self, accrediting_authority_did, dlt):
        self.accrediting_authority_did = accrediting_authority_did
        self.accredited_entities = {}  # Map DID -> metadata (tipo, timestamp, ecc.)
        self.dlt = dlt

    def accredit_entity(self, caller_did, target_did, entity_type):
        # Controllo se il chiamante è l'ente di accreditamento
        print(caller_did, self.accrediting_authority_did)
        if caller_did != self.accrediting_authority_did:
            print(f"[AccreditationRegistry] ERRORE: {caller_did} non è autorizzato ad accreditare.")
            return False

        did_str = target_did["id"]
        print(self.accredited_entities)
        if did_str in self.accredited_entities:
            print(f"[AccreditationRegistry] DID già accreditato: {did_str}")
            return False

        if entity_type not in ["Issuer", "Verifier"]:
            return False

        self.accredited_entities[did_str] = {
            "type": entity_type,
            "timestamp": time.time()
        }

        # Registrazione dell'accreditamento sulla blockchain
        block_data = {
            "type": "Accreditation",
            "accrediting_authority": caller_did,
            "accredited_did": did_str,
            "did_document": target_did,
            "entity_type": entity_type,
            "timestamp": time.time()
        }
        self.dlt.add_block(block_data)
        print(f"[DLT] Accredito registrato on-chain per DID: {did_str}")
        print(f"[AccreditationRegistry] {entity_type} accreditato con DID: {did_str}")
        return True

    def is_accredited(self, did):
        return did in self.accredited_entities

    def list_accredited(self):
        return list(self.accredited_entities.keys())
