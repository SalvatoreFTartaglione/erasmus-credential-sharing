import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import json
from cryptography.hazmat.backends import default_backend

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
        elif entity_type == "Student":
            did_document["name"] = entity_name
            
        return did_document
    
    
    def resolve_did(self, did: str, did_type: str):
        """
        Risolve un DID per recuperare il suo DID Document corrispondente dalla DLT.
        Questo metodo interroga lo smart contract AccreditationRegistry o StudentDIDRegistry sulla DLT.
        :param did: Il DID da risolvere.
        :param did_type: Il tipo del caller (Issuer/Verifier/Student) per capire su quale registry operare.
        :return: Il DID Document associato al DID (come dizionario Python), o None se non trovato.
        """
        try:
            retrieved_data = None

            if did_type in ["Issuer", "Verifier"]:
                retrieved_data = self.accreditation_registry.get_did_document(did)
            elif did_type == "Student":
                retrieved_data = self.student_did_registry.get_did_document(did)
            else:
                return None
            
            did_document = None
            if retrieved_data:
                if isinstance(retrieved_data, dict) and 'did_document_json' in retrieved_data:
                    # Se è un dizionario che incapsula una stringa JSON del DID Document
                    try:
                        did_document = json.loads(retrieved_data['did_document_json'])
                    except json.JSONDecodeError:
                        return None
                elif isinstance(retrieved_data, dict):
                    # Se è già il DID Document come dizionario Python
                    did_document = retrieved_data
            
            return did_document
        
        except AttributeError:
            # ERRORE: L'oggetto registry non ha il metodo get_did_document o attributo non valido.
            return None
        except Exception:
            # Errore generico durante la risoluzione del DID
            return None



    def get_public_key_from_did_document(self, did_document: dict, key_id: str = None):
        """
        Estrae e carica la chiave pubblica da un DID Document.
        key_id può essere usato per selezionare una specifica chiave se ce ne sono più.
        """
        print(f"  DIDManager: Estraendo chiave pubblica dal DID Document.")
        if 'verificationMethod' not in did_document:
            raise ValueError("DID Document non contiene 'verificationMethod'.")
        
        for method in did_document['verificationMethod']:
            # Cerca la chiave basandosi sull'ID completo
            # o semplicemente prende la prima chiave disponibile se key_id è None
            if key_id and method.get('id') == key_id or not key_id:
                if 'publicKeyPem' in method:
                    pem_bytes = method['publicKeyPem'].encode('utf-8')
                    try:
                        public_key = serialization.load_pem_public_key(
                            pem_bytes,
                            backend=default_backend()
                        )
                        print(f"  DIDManager: Chiave pubblica '{method.get('id', 'N/A')}' caricata con successo.")
                        return public_key
                    except Exception as e:
                        print(f"  DIDManager: ERRORE caricamento chiave pubblica dal PEM: {e}")
                        raise
        raise ValueError(f"Chiave pubblica con ID '{key_id}' non trovata nel DID Document o formato non supportato.")


    """ 
    def get_public_key_from_did_document(self, did_document: dict) -> str | None:
        if 'verificationMethod' in did_document and len(did_document['verificationMethod']) > 0:
            # Assumiamo che la prima verificationMethod contenga la chiave principale
            for vm in did_document['verificationMethod']:
                if 'publicKeyPem' in vm:
                    return vm['publicKeyPem']
        return None 
    """


    def get_x509_certificate_from_did_document(self, did_document: dict):
        """
        Recupera un certificato X.509 da un DID Document già parsato (dizionario Python).
        
        :param did_document: Il DID Document come dizionario Python.
        :return: L'oggetto x509.Certificate se trovato, altrimenti None.
        """
        print("DIDManager: Tentativo di recuperare certificato X.509 dal DID Document.")
        
        # Ci aspettiamo che did_document sia già un dizionario Python.
        if not isinstance(did_document, dict):
            print("DIDManager: ERRORE: L'input non è un dizionario DID Document valido.")
            return None

        # Accediamo direttamente alla chiave 'service'
        if 'service' in did_document:
            print('DIDManager: Chiave "service" trovata nel DID Document.')
            for service in did_document['service']:
                # Controlla il tipo di servizio e il formato del certificato
                if service.get('type') == 'X509CertificateService' and \
                   'serviceEndpoint' in service and \
                   'certificatePem' in service['serviceEndpoint']:
                    
                    cert_pem = service['serviceEndpoint']['certificatePem']
                    try:
                        print("DIDManager: Trovato certificato X.509 in formato PEM. Caricamento in corso...")
                        # Decodifica la stringa PEM in bytes e carica il certificato
                        return x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
                    except Exception as e:
                        print(f"DIDManager: ERRORE durante il caricamento del certificato X.509 dal DID Document: {e}")
                        return None # Errore nel caricamento del certificato specifico
            print("DIDManager: Nessun servizio di tipo 'X509CertificateService' valido trovato nel DID Document.")
        else:
            print('DIDManager: Chiave "service" NON trovata nel DID Document.')

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