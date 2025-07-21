from Utils.TLS import TLS
from Utils.Wallet import Wallet
import os
import random

class Student:
    def __init__(self, name, did_manager, student_did_registry, issuer, verifier, ae, accreditation_registry, credential_status_registry):
        self.name = name
        self.entity_type = "Student"
        self.did_manager = did_manager
        self.student_did_registry = student_did_registry
        self.did = did_manager.generate_did(self.name)
        self.public_key, self.private_key = did_manager.generate_keys()
        self.did_document = did_manager.build_did_document(did=self.did, public_key=self.public_key, entity_name=self.name, entity_type=self.entity_type)
        self._register_student_did_document()
        self.wallet = None
        self.issuer = issuer
        self.verifier = verifier
        self.email = None
        self.password = None
        self.ae = ae
        self.accreditation_registry = accreditation_registry
        self.credential_status_registry = credential_status_registry

    def get_name(self):
        return self.name

    def create_wallet(self):
        self.wallet = Wallet(student_name = self.name,
                            student_did = self.did, 
                            student_did_document = self.did_document, 
                            student_public_key=self.public_key, 
                            student_private_key=self.private_key, 
                            issuer=self.issuer,
                            verifier=self.verifier,
                            ae=self.ae,
                            did_manager=self.did_manager,
                            accreditation_registry=self.ae.accreditation_registry,
                            credential_status_registry=self.credential_status_registry
                            )

    def get_wallet(self):
        return self.wallet if self.wallet else None

    def request_credential(self):
        """Metodo che simula la richiesta di una credenziale all'Issuer da parte dello 
        Studente tramite il suo Wallet il quale chiama il quale si occupa di mandare 
        la richiesta effettiva all'Issuer che poi la gestisce.
        return: La credenziale ricevuta dall'Issuer, se la richiesta ha successo.
                altrimenti ritorna None"""
        if self.wallet is None:
            print(f"Lo studente {self.name} non possiede un wallet in cui salvare la credenziale")
            return None
        
        # Richiedi la credenziale all'Issuer tramite il Wallet
        success, credential = self.wallet.request_credential_to_Issuer(self.did)
        
        if success:
            print(f"Credenziale richiesta con successo per {self.name}.")
            return credential
        else:
            print(f"Errore nella richiesta della credenziale per {self.name}.")
            return None


    def verify_requested_credential(self, credential):
        """
        Verifica che la Verifiable Credential (VC) ricevuta dall'Issuer sia corretta,
        controllando l'integrità degli attributi tramite la Merkle Root e la sua firma digitale.
        La Merkle Root è calcolata dagli attributi e confrontata con quella firmata dall'Issuer
        per garantire autenticità e integrità.
        """
        integrity_check = self.wallet.verify_credential(credential)
        
        if integrity_check:
            print('La credenziale ricevuta non è compromessa')
            return True
        else:
            print('La credenziale ricevuta è compromessa')
            return False
            
        
        
        
        
    def send_vp(self):
        if self.wallet is None:
            print(f"Lo studente {self.name} non possiede un wallet da cui creare una VP")
            return
        self.wallet.generateDid()
        self.wallet.send_vp_to_Verifier()


    def create_email_and_password(self):
        random_number = random.randint(1, 10)
        self.email = f"{self.name}.{random_number}@studenti.erasmus.it"
        self.password = f"{self.name}.{random_number}?!pass"
        credentials = f"Email: {self.email}\nPassword: {self.password}\n"

        # Crea la directory se non esiste
        dir_path = os.path.abspath("Student_Credentials")
        os.makedirs(dir_path, exist_ok=True)
        # Costruisci il percorso completo del file
        filename = f"{self.name}_credentials.txt"
        filepath = os.path.join(dir_path, filename)
        # Scrivi le credenziali nel file
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(credentials)

        print(f"Credenziali generate per {self.name} e salvate in: {filepath}")



    def get_email(self):
        return self.email


    def get_password(self):
        return self.password


    def send_public_key_to_issuer(self):
        # print(f"Public key before encrypt: {self.public_key}")
        public_key_obj = TLS.load_public_key_from_pem(self.public_key)
        self.wallet.pubk_to_issuer(self.did, public_key_obj, self.public_key)
        
        
    def _register_student_did_document(self):
        """ Registra il DID Document dello Studente nella DLT tramite StudentDIDRegistry.
        """
        self.student_did_registry.register_student_did_document( did=self.did, did_document=self.did_document)
