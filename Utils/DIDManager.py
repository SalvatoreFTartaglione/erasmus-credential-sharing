import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class DIDManager:
    def __init__(self, accreditation_registry, credential_status_registry, student_did_registry):
        """
        Inizializza il DIDManager con i registri necessari.
        """
        self.accreditation_registry = accreditation_registry
        self.credential_status_registry = credential_status_registry
        self.student_did_registry = student_did_registry


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


    def build_did_document(self, did, entity_name, public_key, entity_type):
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
            "assertionMethod": [key_id]
        }
        # Aggiungi servizi specifici in base al tipo di entità (issuer verifier e ae solo)
        if entity_type == "Issuer":
            did_document["service"] = [{
                "id": f"{did}#issuer-endpoint",
                "type": "IssuerService",
                "serviceEndpoint": f"https://api.{entity_name.lower().replace(' ', '').replace('à', 'a')}.org"
            }]
        elif entity_type == "Verifier":
            did_document["service"] = [{
                "id": f"{did}#presentation-request-endpoint",
                "type": "PresentationRequestService",
                "serviceEndpoint": f"https://verify.{entity_name.lower().replace(' ', '').replace('à', 'a')}.org/request"
            }]
        elif entity_type == "Certificate Authority":
            did_document["service"] = [{
                "id": f"{did}#accreditation-request-endpoint",
                "type": "AccreditationRequestService",
               "serviceEndpoint": f"https://verify.{entity_name.lower().replace(' ', '').replace('à', 'a')}.org/request"
            }]    
            
        return did_document
    
    
    def resolve_did(did, did_type):
        """
        Risolve un DID per recuperare il suo DID Document corrispondente dalla DLT.
        Questo metodo interroga lo smart contract AccreditationRegistry sulla DLT.
        :param did: Il DID da risolvere.
        :param type: Il tipo del caller (Issuer/Verifier/Student) per capire su quale registry operare.
        :return: Il DID Document associato al DID, o None se non trovato
        """
        try:
            # Contolla se il tipo del caller per capire se operare su accreditation_registry (Issuer/Verifier)
            # o credential_status_registry (Student)
            if did_type in ["Issuer", "Verifier"]:
                did_document = self.accreditation_registry.get_did_document(did)
            elif did_type == "Student":
                did_document = self.student_did_registry.get_did_document(did)
            else:
                print(f"Tipo di caller non riconosciuto: {did_type}")
                return None
            
            if did_document:
                return did_document
            else:
                print(f"DID Document non trovato sulla dlt per il DID: {did}")
                return None
        
        except Exception as e:
            print(f"Errore durante la risoluzione del DID {did} di {did_type} con eccezione = {e}")
            return None


    def get_public_key_from_did_document(self, did_document: dict) -> str | None:
        """
        Estrae la chiave pubblica in formato PEM da un DID Document.
        :param did_document: Il DID Document.
        :return: La chiave pubblica in formato PEM (stringa) o None se non trovata.
        """
        if 'verificationMethod' in did_document and len(did_document['verificationMethod']) > 0:
            # Assumiamo che la prima verificationMethod contenga la chiave principale
            for vm in did_document['verificationMethod']:
                if 'publicKeyPem' in vm:
                    return vm['publicKeyPem']
        return None


    def get_x509_certificate_from_did_document(self, did_document: dict) -> str | None:
        """
        Estrae il certificato X.509 in formato PEM da un DID Document (se presente nel service endpoint).
        :param did_document: Il DID Document.
        :return: Il certificato X.509 in formato PEM (stringa) o None se non trovato.
        """
        if 'service' in did_document:
            for service in did_document['service']:
                if service.get('type') == 'X509CertificateService' and 'serviceEndpoint' in service:
                    return service['serviceEndpoint'].get('certificatePem')
        return None


    def get_public_key_object_from_pem(self, public_key_pem: str):
        """
        Converte una chiave pubblica PEM (stringa) in un oggetto chiave pubblica per cryptography.
        """
        try:
            return serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
        except Exception as e:
            print(f"Errore nel caricamento della chiave pubblica PEM: {e}")
            return None