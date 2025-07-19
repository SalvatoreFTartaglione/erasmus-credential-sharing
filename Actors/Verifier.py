import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import datetime

from Utils.DIDManager import DIDManager

class Verifier:
    
    def __init__(self, name, ae, did_manager):
        self.name = name
        self.did = None
        self.did_manager = did_manager
        self.ae = ae
        self.public_key = None
        self.private_key = None 
        self.did_document = None
        self.entity_type = "Verifier"
        self.is_verified = False
        self.ae_ca_certificate = None # Store AE's CA certificate for validation
        self.accreditation_x509_certificate = None # Oggetto x509.Certificate
        self.accreditation_vc = None # Dizionario VC (JSON)
        
    # Request accreditation for the Verifier
    # This method generates a DID, public key, and DID document, then requests accreditation from
    def accredit_request(self):
        self.did = self.did_manager.generate_did(self.name)
        self.public_key, self.private_key = self.did_manager.generate_keys()
        
        # Inizializza il DID Document locale del Verifier prima di inviarlo per l'accreditamento all'AE
        self.did_document = self.did_manager.build_did_document(
            did=self.did, public_key=self.public_key, entity_name=self.name, entity_type=self.entity_type
        )
        
        # Accreditation request to the AE: did document updated with X.509 certificate
        # anche self.did_document viene aggiornato perchè è passato per riferimento alla funzione
        self.is_verified, self.accreditation_x509_certificate, self.accreditation_vc = self.ae.giveAccreditation(
            target_did_document=self.did_document, 
            entity_type=self.entity_type
        )
        if self.is_verified:
            # print(f"Verifier accreditato con did -> {self.did}")
            # salva la vc in un directory
            self._save_vc(self.accreditation_vc)
            return True
        else:
            # print('Errore di accreditamento.\nEnte non accreditato.')
            return False
        
    
    # DID Document resolution 
    def resolve_did_document(self):
        """
        Risolve un DID per recuperare il suo DID Document corrispondente dalla DLT. 
        Questo metodo interroga lo smart contract AccreditationRegistry sulla DLT.
        """
        pass
        
    
    # Nuovo metodo per verificare una presentazione (VP)
    def verify_presentation(self, verifiable_presentation: dict) -> bool:
        """
        Verifica una Verifiable Presentation (VP) presentata da uno Studente.
        Implementa i passaggi da 7.A a 7.F del WP2.
        """
        
        # --- Step 7.A: Verifica la firma della VP ---
        print("7.A: Inizio verifica della Firma della Presentazione dello Studente...")
        try: 
            # 1. Estrarre il DID dello Studente dalla VP
            student_did = verifiable_presentation.get("holder")
            if not student_did:
                print("Errore: DID dello Studente non trovato nella VP.")
                return False
            
            # Risoluzione del DID dello studente per ottenere il suo DID Document
            student_did_document = self.did_manager.resolve_did(student_did, "Student")
            if not student_did_document:
                print(f"7.A: Errore: Impossibile risolvere il DID dello Studente: {student_did}.")
                return False
        except Exception as e:
            print(f"Errore durante l'estrazione del DID dello Studente: {e}")
            return False
        
        
        # --- Step 7.B ---#
        # --- Step 7.C ---#
        # --- Step 7.D ---#
        # --- Step 7.E ---#
        # --- Step 7.F ---#
            
    
    
    
    def _save_vc(self, vc):
        """
        Salva la Verifiable Credential in un file JSON.
        """
        # Crea la directory VCs se non esiste
        os.makedirs("VCs", exist_ok=True)
        # Costruisci il nome del file
        filename = f"VCs/_VC{self.name}.json"
        # Salva il contenuto della VC
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.accreditation_vc, f, indent=2, ensure_ascii=False)


    # Helper per verificare una firma RSA 
    def _verify_rsa_signature(self, public_key, signed_data, signature):
        """
        Verifica una firma RSA utilizzando lo schema PSS e SHA256.
        :param public_key: Chiave pubblica dell'entità che ha firmato.
        :param signed_data: Il payload originale che è stato firmato (bytes).
        :param signature: La firma da verificare (bytes).
        :return: True se la firma è valida, False altrimenti.
        """
        try:
            public_key.verify(
                signature,
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            # print(f"Errore di verifica firma: {e}") 
            return False