from Utils.DIDManager import DIDManager
import os
import json
from Utils.TLS import TLS
from cryptography.hazmat.primitives import serialization

class Issuer:
    def __init__(self, name, dlt, ae, credential_registry, did_manager):
        self.name = name
        self.did = None
        self.dlt = dlt
        self.did_manager = did_manager
        self.ae = ae
        self.public_key = None
        self.private_key = None
        self.did_document = None
        self.entity_type = "Issuer"
        self.is_verified = False
        self.credential_registry = credential_registry
        self.ae_ca_certificate = None # Store AE's CA certificate for validation
        self.accreditation_x509_certificate = None # Oggetto x509.Certificate
        self.accreditation_vc = None # Dizionario VC (JSON)

    def accredit_request(self):
        # print(f"Accreditamento dell\'Issuer {self.name}")
        self.did = self.did_manager.generate_did(self.name)
        self.public_key,self.private_key = self.did_manager.generate_keys()

        # Inizializza il DID Document locale dell'Issuer prima di inviarlo per l'accreditamento all'AE
        self.did_document = self.did_manager.build_did_document(
            did = self.did, public_key= self.public_key, entity_name = self.name, entity_type = self.entity_type
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


    def release_credential(self, entity_type):
        if self.is_verified and entity_type == "Student":
            # rilascia una credenziale
            credential_hash = None
            self.credential_registry.register_credential(credential_hash=credential_hash, issuer_did=self.did)
            

    # def request_credential(self, subject_did):
    #     if not self.is_verified:
    #         print("[ERRORE] Issuer non verificato.")
    #         return
    #     return self.credential_builder.build_credential(subject_did=subject_did)

    def add_public_key_of_student(self, encrypted_key, iv, ciphertext):
        aes_key = TLS.server_receive_tls_key(encrypted_key, TLS.load_private_key_from_pem(self.private_key))
        plaintext = TLS.decrypt_message_aes(aes_key, iv, ciphertext)
        print(f"Message encrypted: {ciphertext}")
        print(f"Message decrypted: {plaintext}")
        # Estrai DID e chiave pubblica
        did, pubk_pem = plaintext.decode().split("||")

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

    def get_public_key(self):
        return self.public_key
