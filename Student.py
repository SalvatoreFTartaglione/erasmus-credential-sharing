from TLS import TLS
from Wallet import Wallet
import os
import random

class Student:
    def __init__(self, name, did_manager, issuer):
        self.name = name
        self.did_manager = did_manager
        self.did = did_manager.generate_did(self.name)
        self.public_key, self.private_key = did_manager.generate_keys()
        self.wallet = None
        self.issuer = issuer
        self.email = None
        self.password = None

    def get_nome(self):
        return self.name

    def create_wallet(self):
        self.wallet = Wallet(did_manager=self.did_manager, issuer=self.issuer, verifier=1)
        self.wallet.generateDid()

    def get_wallet(self):
        return self.wallet if self.wallet else None

    def credential_request(self):
        if self.wallet is None:
            print(f"Lo studente {self.name} non possiede un wallet in cui salvare successivamente la credenziale")
            return
        self.wallet.request_credential_to_Issuer(self.did)

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

        filename = f"{self.name}_credentials.txt"
        filepath = os.path.abspath(filename)

        with open(filepath, "w") as file:
            file.write(credentials)

        print(f"Credenziali generate per {self.name} e salvate in: {filepath}")

    def get_email(self):
        return self.email

    def get_password(self):
        return self.password

    def send_public_key_to_issuer(self):
        print(f"Public key before encrypt: {self.public_key}")
        public_key_obj = TLS.load_public_key_from_pem(self.public_key)
        self.wallet.pubk_to_issuer(self.did, public_key_obj, self.public_key)
