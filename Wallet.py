import uuid
from TLS import TLS
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class Wallet:
    def __init__(self, did_manager, issuer, verifier):
        self.did = None
        self.did_manager = did_manager
        self.public_key , self.private_key = did_manager.generate_keys()
        self.entity_name = "Wallet_" + str(uuid.uuid4())
        self.credential = None
        self.issuer = issuer
        self.verifier = verifier

    def get_did(self):
        return self.did

    def generateDid(self):
        self.did = self.did_manager.generate_did(entity_name=self.entity_name)

    def request_credential_to_Issuer(self, student_did):
        if self.did is None:
            print("Questo wallet non ha un did, NON è possibile continuare...")
            return
        print(f"Sono il wallet {self.did} e faccio una richiesta di credenziale all'Issuer")
        self.generateDid()
        self.credential = self.issuer.request_credential(subject_did=self.did)
        if self.credential is not None:
            print(self.credential)
            return
        print("[WALLET] ERRORE: La richiesta non è andata a buon fine")


    def send_vp_to_Verifier(self):
        if self.did is None:
            print("Questo wallet non ha un did, NON è possibile continuare...")
            return
        if not self.credential:
            print("Non c'è una credenziale valida")
            return
        print(f"Sono il wallet {self.did} e invio una VP al Verifier")

    def pubk_to_issuer(self, did, public_key_obj, public_key_pem):
        encrypted_key, aes_key = TLS.simulate_tls_handshake(
            client_private_key=None,
            client_public_key=self.public_key,
            server_public_key=TLS.load_public_key_from_pem(self.issuer.get_public_key())
        )

        message = f"{did}||{public_key_pem}"
        iv, ciphertext = TLS.encrypt_message_aes(aes_key, message.encode())
        print(f"Message before encrypt: {message}")
        print(f"Message after encrypt: {ciphertext}")
        self.issuer.add_public_key_of_student(encrypted_key, iv, ciphertext)


