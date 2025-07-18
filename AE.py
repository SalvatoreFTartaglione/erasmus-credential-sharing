import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption
import datetime
from cryptography.hazmat.backends import default_backend

class AE:
    
    def __init__(self, did,contract):
        self.name = 'Ente di Accreditamento'
        self.did = did
        self.contract = contract     # istanza del contratto AccreditationRegistry
        # Generazione della coppia di chiavi RSA per l'AE 
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        
        # Creazione di un certificato X.509 auto-firmato per l'AE 
        self.ca_certificate = self._generate_AE_X509_certificate(self.did, self.public_key, self.private_key)
    
    def getDid(self):
        return self.did


    # Metodo per accreditare un Issuer o un Verifier
    def giveAccreditation(self, target_did, entity_type):
        
        # 1. Estrarre la chiave pubblica dell'entità dal suo DID Document
        target_public_key_pem = None
        target_public_key = None
        target_did_id = target_did.get('id')
        # Cerca il campo 'publicKeyPem' all'interno di 'verificationMethod'
        if 'verificationMethod' in target_did and len(target_did['verificationMethod']) > 0:
            for vm in target_did['verificationMethod']:
                if 'publicKeyPem' in vm:
                    target_public_key_pem = vm['publicKeyPem']
                    # Carica la chiave pubblica dal formato PEM
                    target_public_key = serialization.load_pem_public_key(
                        target_public_key_pem.encode(),
                        backend=default_backend() # Aggiungi backend
                    )
                    break # Trovata la chiave, esci dal ciclo
        # Se la chiave non viene trovata, stampa un messaggio di errore
        if not target_public_key:
            print(f"AE: Errore: Chiave pubblica dell'entità {target_did_id} non trovata nel DID Document per la certificazione X.509.")
            return False

        
        # 2. Creare e firmare il certificato X.509 per l'entità
        signed_certificate_entity = self._generate_X509_certificate_for_entity(
            target_public_key=target_public_key,
            target_did_id=target_did_id,
            entity_type=entity_type, # Passa entity_type qui
            issuer_certificate_subject=self.ca_certificate.subject, # Soggetto del certificato CA (Issuer)
            signer_private_key=self.private_key # Chiave privata dell'AE per firmare
        )

        # Firmare il certificato con la chiave privata dell'AE
        signed_certificate_pem = signed_certificate_entity.public_bytes(serialization.Encoding.PEM).decode()
        #print(f"\n--- DID Document dell'entità PRIMA dell'aggiornamento (per {target_did_id}): ---\n{json.dumps(target_did, indent=2)}")
        
        # 3. Aggiornare il DID Document dell'entità con il riferimento al certificato X.509
        # Questa parte è ora la responsabilità di giveAccreditation
        x509_service = {
            "id": f"{target_did_id}#x509-certificate",
            "type": "X509CertificateService",
            "serviceEndpoint": {
                "certificatePem": signed_certificate_pem # Includi il PEM del certificato X.509
            }
        }
        if 'service' not in target_did:
            target_did['service'] = []
        target_did['service'].append(x509_service)

        # print(f"\n--- DID Document dell'entità DOPO l'aggiornamento (per {target_did_id}): ---\n{json.dumps(target_did, indent=2)}")
         
        # 4. Inviare la transazione all'AccreditationRegistry con il DID Document aggiornato
        outcome = self.contract.accredit_entity(
            caller_did=self.did, 
            target_did=target_did, # Questo DID Document ora ha il cert X.509
            entity_type=entity_type,
        )

        if outcome:
            print(f"AE: Accredito DLT e rilascio X.509 completati per {target_did_id}.")
            return True
        else:
            print(f"AE: Errore durante l'accreditamento DLT per {target_did_id}.")
            return False
    
    
    # Metodo per generare un certificato X.509 auto-firmato per l'AE
    # Resituisce l'oggetto certificate
    def _generate_AE_X509_certificate(self, ae_did: str, public_key: rsa.RSAPublicNumbers, private_key: rsa.RSAPrivateNumbers):
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Rome"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Ente di Accreditamento - MUR"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, ae_did), 
        ])
        
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 10) # 10 anni
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        return certificate
        
        
    # Metodo (privato) per generare un certificato X.509 per Issuer/Verifier, firmato dall'AE
    # Resituisce l'oggetto certificate
    def _generate_X509_certificate_for_entity(self, target_public_key, target_did_id, entity_type, issuer_certificate_subject, signer_private_key):
        builder = x509.CertificateBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, f"Accredited {entity_type}"), # Usa il parametro entity_type
                x509.NameAttribute(x509.NameOID.COMMON_NAME, target_did_id),
            ])
        ).issuer_name(
            issuer_certificate_subject # Soggetto del certificato CA (AE)
        ).public_key(
            target_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 3) # Certificato valido 3 anni
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Firma il certificato con la chiave privata dell'AE
        signed_certificate = builder.sign(signer_private_key, hashes.SHA256(), default_backend())
        
        return signed_certificate 