import uuid
from Utils.TLS import TLS
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class Wallet:
    def __init__(self, student_did, student_did_document, student_public_key, student_private_key, issuer, verifier):
        self.entity_name = "Wallet_" + str(uuid.uuid4())
        self.credential = None
        self.student_did = student_did
        self.student_did_document = student_did_document
        self.student_public_key = student_public_key
        self.student_private_key = student_private_key
        self.issuer = issuer
        self.verifier = verifier
        

    def get_student_did(self):
        return self.student_did


    def get_student_did_document(self):
        return self.student_did_document


    def request_credential_to_Issuer(self, student_did):
        print(f"Sono il wallet di {self.student_did} e faccio una richiesta di credenziale all'Issuer")
        
        self.credential = self.issuer.request_credential(subject_did=self.student_did)
        
        if self.credential is not None:
            print(self.credential)
            return
        
        print("[WALLET] ERRORE: La richiesta non è andata a buon fine")


    def send_vp_to_Verifier(self):
        if not self.credential:
            print("Non c'è una credenziale valida")
            return
        print(f"Sono il wallet di {self.student_did} e invio una VP al Verifier")


    def pubk_to_issuer(self, did, public_key_obj, public_key_pem):
        encrypted_key, aes_key = TLS.simulate_tls_handshake(
            client_private_key=None,
            client_public_key=self.student_public_key,
            server_public_key=TLS.load_public_key_from_pem(self.issuer.get_public_key())
        )

        message = f"{did}||{public_key_pem}"
        iv, ciphertext = TLS.encrypt_message_aes(aes_key, message.encode())
        print(f"Message before encrypt: {message}")
        print(f"Message after encrypt: {ciphertext}")
        self.issuer.add_public_key_of_student(encrypted_key, iv, ciphertext)


