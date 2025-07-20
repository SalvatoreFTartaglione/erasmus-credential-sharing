from Utils.DIDManager import DIDManager
import os
import json
from Utils.TLS import TLS
from cryptography.hazmat.primitives import serialization
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from cryptography.hazmat.backends import default_backend


class Issuer:
    def __init__(self, name, dlt, ae, credential_status_registry, did_manager):
        self.name = name
        self.did = None
        self.dlt = dlt
        self.did_manager = did_manager
        self.ae = ae
        self.public_key = None
        self.private_key = None
        self.did_document = None
        self.entity_type = "Issuer"
        self.is_verified = False
        self.credential_status_registry = credential_status_registry
        self.ae_ca_certificate = None # Store AE's CA certificate for validation
        self.accreditation_x509_certificate = None # Oggetto x509.Certificate
        self.accreditation_vc = None # Dizionario VC (JSON)

    def accredit_request(self):
        # print(f"Accreditamento dell\'Issuer {self.name}")
        self.did = self.did_manager.generate_did(self.name)
        self.public_key,self.private_key = self.did_manager.generate_keys()

        # Inizializza il DID Document locale dell'Issuer prima di inviarlo per l'accreditamento all'AE
        self.did_document = self.did_manager.build_did_document(
            did = self.did, public_key= self.public_key, entity_name = self.name, entity_type = self.entity_type
        )

        # Accreditation request to the AE: did document updated with X.509 certificate
        # anche self.did_document viene aggiornato perchè è passato per riferimento alla funzione
        self.is_verified, self.accreditation_x509_certificate, self.accreditation_vc = self.ae.giveAccreditation(
            target_did_document=self.did_document,
            entity_type=self.entity_type
        )
        if self.is_verified:
            # print(f"Verifier accreditato con did -> {self.did}")
            # salva la vc in un directory
            self._save_vc(self.accreditation_vc)
            return True
        else:
            # print('Errore di accreditamento.\nEnte non accreditato.')
            return False


    def release_credential(self, entity_type):
        if self.is_verified and entity_type == "Student":
            # rilascia una credenziale
            credential_hash = None
            self.credential_status_registry.register_credential(credential_hash=credential_hash, issuer_did=self.did)
            

    def request_credential(self, subject_did):
        """
        Metodo che l'Issuer espone per ricevere richieste di credenziali.
        Qui l'Issuer verifica l'identità dello studente e poi chiama il suo stesso
        metodo issue_credential per emettere effettivamente la VC.
        """
        print(f"\nIssuer {self.name}: Ricevuta richiesta credenziale da {subject_did}.")
        # l'Issuer accetta la richiesta e procede con l'emissione (senza verificare l'identità dello 
        # studente per semplicità)
        
        # Recupera il nome dello studente dal DID Document (se lo studente lo ha messo)
        student_did_document = self.did_manager.resolve_did(subject_did, 'Student')
        student_name = "Studente Sconosciuto"
        if student_did_document and 'name' in student_did_document:
            student_name = student_did_document['name']
        
        credential = self.issue_credential(subject_did=subject_did, subject_name=student_name)
        return credential




    def issue_credential(self, subject_did, subject_name="Studente Test", course="Data Science", grade="27/30"):
        """
        Genera una credenziale con i campi specificati dal file APS_credential.json.
        """
        print(f"\nIssuer {self.name}: Inizio emissione Credenziale per lo Studente {subject_name} ({subject_did}).")
        
        issuance_date_obj = datetime.datetime.now(datetime.timezone.utc)
        expiration_date_obj = issuance_date_obj + datetime.timedelta(days=3 * 365) # Approx 3 years

        credential_subject_data = {
            "id": subject_did,
            "Name": subject_name, # Updated to "Name" as per APS_credential.json
            "birthDate": "2002-09-19", # Hardcoded from example
            "nationality": "IT",      # Hardcoded from example
            "email": "c.rosa10@studenti.unisa.it", # Hardcoded from example
            "homeUniversity": {
                "name": "Università degli Studi di Salerno",
                "country": "Italia",
                "ErasmusCode": "I SALERNO132"
            },
            "hostUniversity": {
                "name": "Université de Rennes",
                "country": "Francia",
                "ErasmusCode": "F RENNES1497"
            },
            "mobilityPeriod": {
                "startDate": "2025-09-22",
                "endDate": "2026-02-28"
            },
            "learningAgreement": {
                "semester": "2025/2026 - Semestre 1",
                "agreedCourses": [
                    {
                        "title": course, # Use passed course
                        "language": "Inglese",
                        "ects": 9,
                        "status": "Superato",
                        "grade": grade, # Use passed grade
                        "honor": False
                    },
                    {
                        "title": "Automation",
                        "language": "Inglese",
                        "ects": 9,
                        "status": "Superato",
                        "grade": "30/30",
                        "honor": True
                    },
                    {
                        "title": "Design and Analysis of Algorithms",
                        "language": "Inglese",
                        "ects": 9,
                        "status": "Non Superato",
                        "grade": None,
                        "honor": False
                    },
                    {
                        "title": "Machine Learning",
                        "language": "Inglese",
                        "ects": 9,
                        "status": "Non Svolto",
                        "grade": None,
                        "honor": False
                    },
                    {
                        "title": "Niveau de langue française - A2",
                        "language": "Francese",
                        "ects": 3,
                        "status": "Superato",
                        "grade": "Idoneo",
                        "honor": False
                    }
                ]
            },
            "optionalExperience": {
                "canteen": True,
                "dormitory": True,
                "extracurricularActivities": ["Hackathon Erasmus", "Atelier de théâtre"],
                "optionalCourses": [
                    {
                        "title": "Embedded Systems",
                        "language": "Inglese",
                        "ects": 9,
                        "status": "Non Svolto",
                        "grade": None,
                        "honor": True
                    }
                ]
            }
        }

        # 1. Crea le foglie del Merkle Tree dagli attributi del credentialSubject
        merkle_leaves = []
        # Ordina per coerenza, sebbene per il Merkle Tree l'ordine non sia strettamente necessario
        # per la validità della proof, è buona pratica per la riproducibilità.
        # Per un Merkle Tree di attributi di un CredentialSubject più complesso, è fondamentale
        # serializzare ogni attributo (e sotto-attributo) in un formato canonico prima dell'hashing.
        # Qui useremo una serializzazione JSON ricorsiva per gli attributi più complessi.

        def canonical_json_dump(data):
            # Funzione ricorsiva per creare una stringa JSON canonica per l'hashing
            if isinstance(data, dict):
                return json.dumps({k: canonical_json_dump(data[k]) for k in sorted(data.keys())}, separators=(',', ':'))
            elif isinstance(data, list):
                return '[' + ','.join(canonical_json_dump(item) for item in data) + ']'
            elif isinstance(data, bool):
                return 'true' if data else 'false'
            elif data is None:
                return 'null'
            elif isinstance(data, (int, float)):
                return str(data)
            else:
                return json.dumps(data) # Per stringhe, per gestire correttamente i caratteri speciali

        # Genera hash delle foglie per tutti gli attributi del credentialSubject
        sorted_keys = sorted(credential_subject_data.keys())
        for key in sorted_keys:
            value = credential_subject_data[key]
            # Converti ogni attributo (e i suoi sotto-attributi) in una stringa JSON canonica
            # per l'hashing. La chiave dell'attributo è inclusa nel leaf_data per chiarezza
            # e per evitare collisioni se solo il valore fosse hashed.
            leaf_content = {key: value}
            leaf_data_str = canonical_json_dump(leaf_content)
            merkle_leaves.append(hashes.Hash(hashes.SHA256(), backend=default_backend()).update(leaf_data_str.encode('utf-8')).finalize())

        # Calcola il Merkle Tree e la Merkle Root
        merkle_tree = self._build_merkle_tree(merkle_leaves)
        merkle_root = merkle_tree[0] # La radice è il primo elemento dell'albero completo
        
        # Converte la Merkle Root in base64 per inclusione nella VC
        merkle_root_b64 = base64.b64encode(merkle_root).decode('utf-8')

        # 2. Prepara la VC
        credential_id = f"urn:uuid:{os.urandom(16).hex()}"
        credential_body = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.european-credentials.eu/contexts/education/v1" # Updated context
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "ErasmusMobilityCredential"], # Updated type
            "issuer": { # Updated issuer to object
                "id": self.did,
                "name": self.name
            },
            "issuanceDate": issuance_date_obj.isoformat() + "Z",
            "expirationDate": expiration_date_obj.isoformat() + "Z", # Added expirationDate
            "credentialSubject": credential_subject_data, # Contiene tutti gli attributi
            "merkleRoot": merkle_root_b64 # La Merkle Root è inclusa nella VC
        }

        # 3. Firma la Merkle Root con la chiave privata dell'Issuer
        signature_bytes = self._sign_data(merkle_root)
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

        # 4. Aggiungi la prova (proof) alla VC
        credential_body['proof'] = {
            "type": "RsaSignature2018",
            "created": issuance_date_obj.isoformat() + "Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{self.did}#bbs-key-1", # Updated verificationMethod to match example style
            "merkleRoot": merkle_root_b64, 
            "signatureValue": signature_b64,
            "proofValue": "simulated_proof_value", # Placeholder as per example structure, requires BBS+
            "jws": "simulated_jws" # Placeholder as per example structure, requires JWS/BBS+
        }
        
        # 5. Aggiungi credentialStatus (nuovo blocco)
        credential_body['credentialStatus'] = {
            "id": f"https://revocation.univ-rennes.fr/status/{os.urandom(2).hex()}", # Simulated status ID
            "type": "RevocationList2020Status"
        }

        # 6. Aggiungi accreditation (nuovo blocco)
        # Assuming accreditation dates are relative to credential issuance for simplicity
        accreditation_issued = issuance_date_obj - datetime.timedelta(days=15) # 15 days before credential
        accreditation_valid_until = accreditation_issued + datetime.timedelta(days=3 * 365) # Approx 3 years
        credential_body['accreditation'] = {
            "type": "AccreditationCredential",
            "issuer": "https://agenziaerasmus.it", # Hardcoded from example
            "issued": accreditation_issued.isoformat() + "Z",
            "validUntil": accreditation_valid_until.isoformat() + "Z"
        }
        
        print(f"Issuer {self.name}: Credenziale '{credential_body['type']}' emessa per {subject_name}.")
        return credential_body



    def _build_merkle_tree(self, leaves):
        """Costruisce un Merkle Tree da una lista di hash di foglie."""
        if not leaves:
            return []
        
        # Ensures there's an even number of leaves by duplicating the last one if odd
        if len(leaves) % 2 != 0:
            leaves.append(leaves[-1]) 

        tree = list(leaves) # Initialize the first level of the tree with leaves
        
        # Process levels until only one root hash remains
        while len(tree) > 1:
            next_level = []
            # Hash pairs of nodes from the current level
            for i in range(0, len(tree), 2):
                # Concatenate hashes and then hash the concatenation
                combined_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
                combined_hash.update(tree[i] + tree[i+1])
                next_level.append(combined_hash.finalize())
            
            tree = next_level # Move to the next level
            
            # If the next level has an odd number of nodes, duplicate the last one
            if len(tree) % 2 != 0 and len(tree) > 1:
                tree.append(tree[-1])
        
        return tree # The final element is the Merkle Root


    def _generate_merkle_proof(self, credential_data: dict, selected_attributes: list, merkle_tree_leaves_hashes: list, merkle_tree_structure: list):
        """
        Genera le Merkle Proofs per gli attributi selezionati.
        Questo è un placeholder e l'implementazione reale sarebbe più complessa.
        """
        proofs = []
        for attr_key in selected_attributes:
            if attr_key in credential_data:
                # In una vera implementazione, qui si costruirebbe la proof path
                # dalla foglia all'albero, ma per ora è simulato.
                proofs.append({
                    "attribute": attr_key,
                    "value": credential_data[attr_key],
                    "proof": "simulated_merkle_path_for_" + attr_key # Placeholder
                })
        return proofs


    def _sign_data(self, data_bytes: bytes) -> bytes:
        """
        Firma un array di byte usando la chiave privata dell'Issuer.
        """
        signer = self.primitive_private_key
        signature = signer.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    
    
    
    
    
    def add_public_key_of_student(self, encrypted_key, iv, ciphertext):
        aes_key = TLS.server_receive_tls_key(encrypted_key, TLS.load_private_key_from_pem(self.private_key))
        plaintext = TLS.decrypt_message_aes(aes_key, iv, ciphertext)
        print(f"Message encrypted: {ciphertext}")
        print(f"Message decrypted: {plaintext}")
        # Estrai DID e chiave pubblica
        did, pubk_pem = plaintext.decode().split("||")

    def _save_vc(self, vc):
        """
        Salva la Verifiable Credential in un file JSON.
        """
        # Crea la directory VCs se non esiste
        os.makedirs("VCs", exist_ok=True)
        # Costruisci il nome del file
        filename = f"VCs/_VC{self.name}.json"
        # Salva il contenuto della VC
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.accreditation_vc, f, indent=2, ensure_ascii=False)

    def get_public_key(self):
        return self.public_key

