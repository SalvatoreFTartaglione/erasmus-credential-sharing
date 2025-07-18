import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
from cryptography.hazmat.backends import default_backend
import base64

class AE:
    
    def __init__(self, name, accreditation_registry, did_manager):
        self.name = name 
        self.accreditation_registry = accreditation_registry 
        # Le seguenti operazioni avvengono nel costruttore perche l'AE non ha bisogno di accreditarsi, bensì si accredita 'da sola'
        # Genera il DID dell'AE
        self.did = did_manager.generate_did(self.name)
        
        # genera la chiave pubblica e privata dell'AE
        self.public_key, self.private_key = did_manager.generate_keys()
        
        # Crea il DID Document dell'AE      
        self.did_document = did_manager.build_did_document(did=self.did, public_key=self.public_key, entity_name=self.name)
        
        # coverti chiave pubblica da formato PEM a RSA PublicNumbers
        self.primitive_public_key = serialization.load_pem_public_key(
                        self.public_key.encode(),
                        backend=default_backend() 
                    )
        self.primitive_private_key = serialization.load_pem_private_key(
                        self.private_key.encode(),
                        password=None,
                        backend=default_backend() 
                    )
        
        # Crea il certificato X.509 dell'AE
        self.ca_certificate = self._generate_AE_X509_certificate(self.did, self.primitive_public_key, self.primitive_private_key)

        
        
    def get_did(self):
        """
        Returns the DID of the AE.
        """
        return self.did
    
    

    # Metodo per accreditare un Issuer o un Verifier
    def giveAccreditation(self, target_did_document, entity_type):
        
        # 1. Estrarre la chiave pubblica dell'entità dal suo DID Document
        target_public_key_pem = None
        target_public_key = None
        target_did_id = target_did_document.get('id')
        # Cerca il campo 'publicKeyPem' all'interno di 'verificationMethod'
        if 'verificationMethod' in target_did_document and len(target_did_document['verificationMethod']) > 0:
            for vm in target_did_document['verificationMethod']:
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
            signer_private_key=self.primitive_private_key # Chiave privata dell'AE per firmare
        )

        # Firmare il certificato con la chiave privata dell'AE
        signed_certificate_pem = signed_certificate_entity.public_bytes(serialization.Encoding.PEM).decode()
        
        # 3. Aggiornare il DID Document dell'entità con il riferimento al certificato X.509
        updated_did_document = self.update_did_document_with_x509(target_did_id=target_did_id, signed_pem_certificate=signed_certificate_pem, target_did_document=target_did_document)

        # 4. Inviare la transazione all'AccreditationRegistry con il DID Document aggiornato
        outcome = self.accreditation_registry.accredit_entity(
            caller_did=self.did, 
            target_did=updated_did_document, # Questo DID Document ora ha il cert X.509
            entity_type=entity_type,
        )
        
        # 5. Gestire l'esito dell'accreditamento
        # 5.1 Esito negativo 
        if not outcome:
            print(f"AE: Errore durante l'accreditamento DLT per {target_did_id}.")
            return False, None, None
        # 5.2 Esito positivo
        else:
            accreditation_vc = self._generate_accreditation_vc(entity_type=entity_type, did=self.did, name=self.name, target_did_id=target_did_id)
            return True, signed_certificate_entity, accreditation_vc
            
            
            
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
    
    
    def update_did_document_with_x509(self, target_did_id, signed_pem_certificate, target_did_document):
        """Metodo per aggiornare il DID Document con il certificato X.509."""
        x509_service = {
            "id": f"{target_did_id}#x509-certificate",
            "type": "X509CertificateService",
            "serviceEndpoint": {
                "certificatePem": signed_pem_certificate # Includi il PEM del certificato X.509
            }
        }
        if 'service' not in target_did_document:
            target_did_document['service'] = []
        target_did_document['service'].append(x509_service) 
    
        return target_did_document
    
    
    def _generate_accreditation_vc(self, entity_type, did, name, target_did_id):
        accreditation_vc = {
                "@context": [
                    "https://www.w3.org/2025/credentials/v1",
                    "https://www.w3.org/2025/credentials/examples/v1" 
                ],
                "id": f"urn:uuid:{x509.random_serial_number()}", 
                "type": ["VerifiableCredential", "AccreditationCredential"],
                "issuer": did,      # DID dell'AE
                "issuanceDate": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
                "credentialSubject": {
                    "id": target_did_id,
                    "type": entity_type,
                    "accreditationStatus": "Accredited",
                    "accreditationAuthority": name 
                },
                "proof": {
                    "type": "RsaSignature2025",             # Tipo di proof
                    "created": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
                    "verificationMethod": f"{did}#keys-1", # Riferimento alla chiave di firma dell'AE nel suo DID Document
                    "proofPurpose": "assertionMethod"       # L'AE sta attestando un fatto
                    # 'jws' o 'signatureValue' verrà aggiunto qui dopo la firma
                }
            }
            # Prepara il payload della VC per la firma (senza il campo 'proof.signatureValue' o 'proof.jws')
            # Si serializza il JSON in modo canonico prima di firmare.
            # Rimuovi temporaneamente il campo 'proof' per firmare solo il corpo della VC.
        vc_to_sign = dict(accreditation_vc)
        if 'proof' in vc_to_sign:
            del vc_to_sign['proof']
        # Serializza il payload della VC in bytes
        vc_payload_bytes = json.dumps(vc_to_sign, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        # Firma la VC
        signature_bytes = self._sign_verifiable_credential(vc_payload_bytes)
        
        # Aggiungi la firma alla VC (codificata in base64url come richiesto da JWS)
        # Per le VC W3C standard, si usa spesso JWS. Per semplicità, si userà base64 standard.
        accreditation_vc['proof']['signatureValue'] = base64.b64encode(signature_bytes).decode('utf-8')
        
        return accreditation_vc    
    
    
    # Metodo helper per firmare le Credenziali Verificabili rilasciate a Issuer/Verifier.
    def _sign_verifiable_credential(self, vc_payload_bytes: bytes) -> bytes:
        """
        Firma il payload di una Credenziale Verificabile usando la chiave privata dell'AE.
        Il payload deve essere una rappresentazione canonica (es. JSON serializzato e ordinato).
        Restituisce la firma in bytes.
        """
        signer = self.primitive_private_key
        signature = signer.sign(
            vc_payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
