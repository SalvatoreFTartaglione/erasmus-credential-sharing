import uuid
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class DIDManager:
    def __init__(self, entity_name, pairwise=False):
        self.entity_name = entity_name
        self.pairwise = pairwise
        self.did = None
        self.did_document = None
        self.private_key = None
        self.public_key = None

    def generate_did(self):
        # Simula una generazione decentralizzata di DID
        unique_suffix = uuid.uuid4().hex
        self.did = f"did:{self.entity_name.lower()}:{unique_suffix}"
        return self.did

    def generate_keys(self):
        # Generazione di una coppia RSA 2048 bit
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.private_key = private_key_pem.decode()
        self.public_key = public_key_pem.decode()
        return self.public_key

    def build_did_document(self):
        if not self.did or not self.public_key:
            raise Exception("DID o chiave pubblica non presenti")

        key_id = f"{self.did}#keys-1"
        self.did_document = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": self.did,
            "verificationMethod": [{
                "id": key_id,
                "type": "RsaVerificationKey2018",
                "controller": self.did,
                "publicKeyPem": self.public_key
            }],
            "authentication": [key_id],
            "assertionMethod": [key_id],
            "service": [{
                "id": f"{self.did}#issuer-endpoint",
                "type": "IssuerService",
                "serviceEndpoint": f"https://api.{self.entity_name.lower()}.org"
            }]
        }
        return self.did_document

    def register_on_blockchain(self):
        # Simulazione della registrazione tramite smart contract
        print(f"[Blockchain] Registrazione DID '{self.did}' su AccreditationRegistry...")
        print(f"[Blockchain] DID Document hash: {hashlib.sha256(json.dumps(self.did_document).encode()).hexdigest()}")

    def rotate_did(self):
        # Per attori che richiedono DID rotabili (e.g. lo studente)
        print(f"[DIDManager] Rotazione del DID per {self.entity_name}")
        return self.__class__(self.entity_name, pairwise=True)  # Ritorna una nuova istanza
