import json 
import time

class StudentDIDRegistry:
    def __init__(self, dlt):
        self.dlt = dlt
        self.student_did_documents = {} # Questo dizionario simula lo storage on-chain dei DID Document degli studenti
                                        # la chiave è il DID dello studente e il valore è il DID Document completo
    
    
    def register_student_did_document(self, did: str, did_document: dict) -> bool:
            """
            Registra un DID Document per uno studente sulla DLT simulata.
            Un DID Document può essere registrato una sola volta per DID.
            """
            if not did or not did_document:
                print("[StudentDIDRegistry] ERRORE: DID o DID Document non validi per la registrazione.")
                return False

            if did in self.student_did_documents:
                print(f"[StudentDIDRegistry] ERRORE: DID dello Studente {did} già registrato.")
                return False

            # In un sistema blockchain reale, qui si emetterebbe una transazione
            # che memorizzerebbe il DID Document (o un suo hash/riferimento)
            self.student_did_documents[did] = did_document

            block_data = {
                "type": "StudentDIDRegistration",
                "did": did,
                "did_document_hash": hash(json.dumps(did_document, sort_keys=True)), 
                "timestamp": time.time()
            }
            self.dlt.add_block(block_data)
            # print(f"[DLT] DID dello Studente {did} e relativo DID Document registrati on-chain.")
            return True


    # Essendo una simulazione per recuperare il did document di uno studente si usa un dizionario 
    # in locale invece di interagire con la blockchain.
    # In un sistema reale, questo metodo interagirebbe con la blockchain per recuperare i dati.
    def get_did_document(self, did: str) -> dict | None:
        """
        Recupera il DID Document completo per un dato DID di uno studente.
        """
        print(f"[StudentDIDRegistry] Richiesta recupero DID Document per lo studente: {did}")
        did_document = self.student_did_documents.get(did)
        if did_document:
            # print(f"[StudentDIDRegistry] DID Document per {did} recuperato con successo.")
            return did_document
        else:
            print(f"[StudentDIDRegistry] DID Document per lo studente {did} non trovato nel registro.")
            return None


    # Metodo per listare tutti i DID degli studenti registrati
    def list_student_dids(self) -> list:
        """Restituisce una lista di tutti i DID degli studenti registrati."""
        return list(self.student_did_documents.keys())
