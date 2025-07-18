import time

class AccreditationRegistry:
    def __init__(self, dlt):
        self.accrediting_authority_did = None
        self.accredited_entities = {}
        self.dlt = dlt

    def set_accrediting_authority(self, accrediting_authority_did):
        self.accrediting_authority_did = accrediting_authority_did
        
    def accredit_entity(self, caller_did, target_did, entity_type):
        # Controllo se il chiamante è l'ente di accreditamento
        #print(caller_did, self.accrediting_authority_did)
        if caller_did != self.accrediting_authority_did:
            #print(f"[AccreditationRegistry] ERRORE: {caller_did} non è autorizzato ad accreditare.")
            return False

        did_str = target_did["id"]
        #print(self.accredited_entities)
        if did_str in self.accredited_entities:
            # print(f"[AccreditationRegistry] DID già accreditato: {did_str}")
            return False

        if entity_type not in ["Issuer", "Verifier"]:
            # print(f"Un'entità di tipo {entity_type} NON può essere certificata")
            return False

        self.accredited_entities[did_str] = {
            "type": entity_type,
            "timestamp": time.time()
        }

        # block data fornisce tutti gli elementi necessari per la registrazione on-chain
        # del processo di accreditamento
        block_data = {
            "type": "Accreditation",
            "accrediting_authority": caller_did,  # Chi ha eseguito l'accreditamento (DID dell'Ente di Accreditamento)
            "accredited_did": did_str,            # Chi è stato accreditato (DID dell'Issuer/Verifier)
            "did_document": target_did,           # Il DID Document completo dell'entità accreditata
            "entity_type": entity_type,           # Il tipo di entità (Issuer o Verifier)
            "timestamp": time.time()              # Quando è avvenuto l'accreditamento
        }
        
        # add data onto the DLT
        self.dlt.add_block(block_data)
        
        
        # print(f"[DLT] Accredito registrato on-chain per DID: {did_str}")
        # print(f"[AccreditationRegistry] {entity_type} accreditato con DID: {did_str}")
        return True

    def get_accreditation_info(self, did):
        return self.accredited_entities.get(did, None)

    def is_accredited(self, did):
        return did in self.accredited_entities

    def list_accredited(self):
        return list(self.accredited_entities.keys())
