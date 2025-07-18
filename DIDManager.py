import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class DIDManager:
    def __init__(self, dlt):
        self.dlt = dlt

    def generate_did(self, entity_name):
        # Normalizza nome
        clean_name = entity_name.lower().replace(" ", "")
        suffix = uuid.uuid4().hex
        did = f"did:{clean_name}:{suffix}"

        return did

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
        private_key = private_key_pem.decode()
        public_key = public_key_pem.decode()
        return public_key, private_key

    def build_did_document(self, did, entity_name, public_key):
        if not did or not public_key:
            raise Exception("DID o chiave pubblica non presenti")

        key_id = f"{did}#keys-1"
        did_document = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "verificationMethod": [{
                "id": key_id,
                "type": "RsaVerificationKey2018",
                "controller": did,     # controller = il proprietario del DID.
                "publicKeyPem": public_key
            }],
            "authentication": [key_id],
            "assertionMethod": [key_id],
            "service": [{
                "id": f"{did}#issuer-endpoint",
                "type": "IssuerService",
                "serviceEndpoint": f"https://api.{entity_name.lower().replace(" ", "").replace("à", "a")}.org"
            }]
        }
        return did_document
