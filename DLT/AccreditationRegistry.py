import time
import json

class AccreditationRegistry:
    def __init__(self, dlt):
        self.accrediting_authority_did = None
        self.accredited_entities = {}
        self.dlt = dlt

    def set_accrediting_authority(self, accrediting_authority_did):
        self.accrediting_authority_did = accrediting_authority_did


    def debug_print(self):
        print("=== Debug: Entità accreditate ===")
        for key, json_doc in self.accredited_entities.items():
            print(f"\n🔑 Chiave: {key}")
            try:
                # Stampa il JSON in modo leggibile con indentazione
                formatted_json = json.dumps(json_doc, indent=4, ensure_ascii=False)
                print(formatted_json)
            except Exception as e:
                print(f"❌ Errore nella formattazione del documento JSON: {e}")


    def accredit_entity(self, caller_did, target_did_document, entity_type):
        # Controllo se il chiamante è l'ente di accreditamento
        if caller_did != self.accrediting_authority_did:
            #print(f"[AccreditationRegistry] ERRORE: {caller_did} non è autorizzato ad accreditare.")
            return False

        did_str = target_did_document["id"]
        #print(self.accredited_entities)
        if did_str in self.accredited_entities:
            # print(f"[AccreditationRegistry] DID già accreditato: {did_str}")
            return False

        if entity_type not in ["Issuer", "Verifier"]:
            # print(f"Un'entità di tipo {entity_type} NON può essere certificata")
            return False

        # salva l'intero DID Document sul registro
        self.accredited_entities[did_str] = {
            "type": entity_type,
            "timestamp": time.time(),
            "did_document_json": json.dumps(target_did_document), # Salva l'intero DID Document come stringa JSON
        }

        # block data fornisce tutti gli elementi necessari per la registrazione on-chain
        # del processo di accreditamento
        block_data = {
            "type": "Accreditation",
            "accrediting_authority": caller_did,  # Chi ha eseguito l'accreditamento (DID dell'Ente di Accreditamento)
            "accredited_did": did_str,            # Chi è stato accreditato (DID dell'Issuer/Verifier)
            "did_document": target_did_document,           # Il DID Document completo dell'entità accreditata
            "entity_type": entity_type,           # Il tipo di entità (Issuer o Verifier)
            "timestamp": time.time()              # Quando è avvenuto l'accreditamento
        }
        
        # add data onto the DLT
        self.dlt.add_block(block_data)
        
        
        # print(f"[DLT] Accredito registrato on-chain per DID: {did_str}")
        print(f"[AccreditationRegistry] {entity_type} accreditato con DID: {did_str}")
        return True
    
    
    # Essendo una simulazione per recuperare il did document di uno studente si usa un dizionario 
    # in locale invece di interagire con la blockchain.
    # In un sistema reale, questo metodo interagirebbe con la blockchain per recuperare i dati.
    def get_did_document(self, did: str) -> dict | None:
        """
        Recupera il DID Document completo per un dato DID di un issuer/verifier.
        """
        print(f"[AccreditaitonRegistry] Richiesta recupero DID Document per l'ente: {did}")
        did_document = self.accredited_entities.get(did)
        if did_document:
            print(f"[AccreditaitonRegistry] DID Document per {did} recuperato con successo.")
            return did_document
        else:
            print(f"[AccreditaitonRegistry] DID Document per lo studente {did} non trovato nel registro.")
            return None

    def get_accreditation_info(self, did):
        return self.accredited_entities.get(did, None)

    def is_accredited(self, did):
        return did in self.accredited_entities

    def list_accredited(self):
        return list(self.accredited_entities.keys())
    
    
    def get_accreditation_status(self, did):
        """
        Restituisce lo stato di accreditamento di un'entità sulla DLT.
        
        :param did: Il DID dell'entità da verificare.
        :return: Un dizionario con lo stato di accreditamento e altre informazioni, o None se non trovato.
        """
        if did in self.accredited_entities:
            return True,
        else:
            return False,
