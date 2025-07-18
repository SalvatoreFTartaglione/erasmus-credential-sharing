import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import datetime

from DIDManager import DIDManager

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
            did=self.did, public_key=self.public_key, entity_name=self.name
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
        