import uuid
from Utils.TLS import TLS
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import datetime
import json
import base64


class Wallet:
    def __init__(self, student_name, student_did, student_did_document, student_public_key, student_private_key, issuer, verifier, ae, accreditation_registry, did_manager):
        self.entity_name = "Wallet_" + str(uuid.uuid4())
        self.credential = None
        self.student_did = student_did
        self.student_name = student_name
        self.student_did_document = student_did_document
        self.student_public_key = student_public_key
        self.student_private_key = student_private_key
        self.issuer = issuer
        self.verifier = verifier
        self.ae = ae
        self.accreditation_registry = accreditation_registry
        self.did_manager = did_manager
        

    def get_student_did(self):
        return self.student_did


    def get_student_did_document(self):
        return self.student_did_document


    def request_credential_to_Issuer(self, student_did):
        """Metodo che simula la richiesta di una credenziale all'Issuer da parte 
            dello Studente tramite il suo Wallet. Questo metodo simula la Fase 4 
            del processo di richiesta della VC da parte dello Studente."""
        
        # print(f"Sono il wallet di {self.student_did} e faccio una richiesta di credenziale all'Issuer {self.issuer.name}.")
        
        if self.issuer is None:
            print("[WALLET] ERRORE: Nessun Issuer associato a questo wallet. Assicurati di chiamare wallet.set_issuer(issuer_instance).")
            return False, None

        # 2. Verifica dell'accreditamento dell'Issuer da parte dello Studente/Wallet
        # Prima di inviare esplicitamente la richiesta per la VC.
        if not self._verify_issuer_accreditation_for_request(self.issuer.did):
            print("[WALLET] ERRORE: L'Issuer non è accreditato o la sua verifica è fallita. Richiesta non inviata.")
            return False, None

        # 3. Invio della richiesta effettiva della VC
        # Il wallet dello studente invia la richiesta all'Università di Rennes (Issuer),
        # includendo il DID dello studente (che contiene/punta alla sua chiave pubblica kpub,S).
        print(f"Wallet: Issuer accreditato. Invio richiesta VC all'Issuer {self.issuer.name} per {student_did}.")
        self.credential = self.issuer.request_credential(subject_did=student_did)
        
        if self.credential is not None:
            print("[WALLET] Credenziale ricevuta con successo dall'Issuer e salvata nel wallet.")
            # stampare la credenziale per verifica
            # print(json.dumps(self.credential, indent=2))
            return True, self.credential
        else:
            print("[WALLET] ERRORE: La richiesta non è andata a buon fine. Nessuna credenziale ricevuta.")
            return False, None


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
        # print(f"Message before encrypt: {message}")
        # print(f"Message after encrypt: {ciphertext}")
        self.issuer.add_public_key_of_student(encrypted_key, iv, ciphertext)



    def _verify_issuer_accreditation_for_request(self, issuer_did: str) -> bool:
        """
        Prima di inviare la richiesta per la VC, lo studente verifica che l’issuer
        sia stato effettivamente accreditato recuperando il certificato che l’ente di
        accreditamento ha rilasciato all’issuer per certificarlo. Solo se questa verifica
        va a buon fine lo studente fa effettivamente richiesta per la VC all’università
        di Rennes.
        """
        # print(f"\nWallet di {self.student_did}: Verifico l'accreditamento dell'Issuer {issuer_did} prima della richiesta.")
        
        # 1. Risolvere il DID dell'Issuer per ottenere il suo DID Document
        # Questo DID Document dovrebbe contenere il certificato X.509 dell'Issuer.
        issuer_did_document = self.did_manager.resolve_did(issuer_did, 'Issuer')
        if not issuer_did_document:
            print(f"   Wallet: Errore: Impossibile risolvere il DID dell'Issuer: {issuer_did}. Richiesta abortita.")
            return False

        # 2. Recuperare il Certificato X.509 dell'Issuer dal suo DID Document
        issuer_x509_cert = self.did_manager.get_x509_certificate_from_did_document(issuer_did_document)
        if not issuer_x509_cert:
            print(f"   Wallet: Errore: Certificato X.509 dell'Issuer {issuer_did} non trovato nel DID Document. Richiesta abortita.")
            return False
        
        # 3. Verificare il certificato X.509 dell'Issuer usando il certificato CA dell'Accreditation Authority
        # Il certificato CA dell'AE è un attributo dell'istanza dell'AE, che è passato al Wallet.
        if not self.ae.ca_certificate:
            print("   Wallet: Errore: Certificato CA dell'Accreditation Authority non disponibile. Impossibile verificare X.509.")
            return False

        if not self._verify_x509_certificate(issuer_x509_cert, self.ae.ca_certificate):
            print(f"   Wallet: Errore: Certificato X.509 dell'Issuer {issuer_did} NON valido o non firmato dalla CA dell'AE. Richiesta abortita.")
            return False
        
        # 4. Interrogare lo smart contract AccreditationRegistry sulla DLT
        # Questo è un controllo aggiuntivo per assicurarsi che l'Issuer sia registrato come "Accredited" sulla DLT.
        print(f"Wallet: Interrogazione AccreditationRegistry sulla DLT per lo stato di {issuer_did}...")
        accreditation_status = self.accreditation_registry.get_accreditation_status(issuer_did)

        if not accreditation_status: 
            print(f"  Wallet: Errore: Issuer {issuer_did} non trovato o non 'Accredited' nell'AccreditationRegistry. Richiesta abortita.")
            return False

        print(f"Wallet: L'Issuer {issuer_did} è accreditato e il suo certificato è valido. Procedo con la richiesta.")
        return True
    
    
    
    def _verify_x509_certificate(self, certificate_to_verify: x509.Certificate, ca_certificate: x509.Certificate) -> bool:
        """
        Verifica un certificato X.509 firmato dalla CA dell'AE.
        Questa funzione è utilizzata dal Wallet per verificare il certificato dell'Issuer.

        :param certificate_to_verify: Il certificato X.509 dell'entità (es. Issuer) da verificare.
        :param ca_certificate: Il certificato della CA (dell'Accreditation Authority).
        :return: True se il certificato è valido e firmato dalla CA, False altrimenti.
        """
        print("Wallet: X.509: Eseguo verifica del certificato...")
        try:
            # 1. Verifica la validità temporale del certificato
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < certificate_to_verify.not_valid_before_utc or now > certificate_to_verify.not_valid_after_utc:
                print("Wallet: X.509: Certificato non valido temporalmente (data corrente fuori range).")
                return False
            
            # 2. Verifica che il certificato sia firmato dal certificato della CA dell'AE
            #    Questo avviene verificando la firma del `certificate_to_verify` usando la chiave pubblica della CA.
            ca_public_key = ca_certificate.public_key()
            ca_public_key.verify(
                certificate_to_verify.signature,
                certificate_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            print("Wallet: X.509: Certificato verificato con successo (valido e firmato dalla CA).")
            return True

        except Exception as e:
            print(f"Wallet: X.509: Errore durante la verifica del certificato: {e}")
            return False
        
        
    def verify_credential(self, credential: dict) -> bool:
        """
        Verifica l'integrità e l'autenticità di una Credenziale Verificabile.
        
        :param credential: La Credenziale Verificabile come dizionario Python.
        :return: True se la credenziale è valida e integra, False altrimenti.
        """
        
        print(f"\n{self.student_name} Inizio verifica della Credenziale.")

        # 1. Verifica la struttura di base della credenziale
        if not all(k in credential for k in ['credentialSubject', 'proof', 'issuer', 'issuanceDate', 'type']):
            print(f"{self.student_name}: ERRORE: La credenziale manca di campi essenziali.")
            return False
        
        if 'merkleRoot' not in credential['proof']:
            print(f"{self.student_name}: ERRORE: La proof della credenziale manca della Merkle Root.")
            return False

        # 2. Recupera la Merkle Root dalla credenziale
        merkle_root_from_credential_b64 = credential['proof']['merkleRoot']
        try:
            merkle_root_from_credential_bytes = base64.b64decode(merkle_root_from_credential_b64)
            print(f"{self.student_name}: Merkle Root letta dalla credenziale: {merkle_root_from_credential_b64}")
        except Exception as e:
            print(f"{self.student_name}: ERRORE: Impossibile decodificare la Merkle Root dalla credenziale (Base64): {e}")
            return False

        # 3. Ricalcola le foglie del Merkle Tree dal credentialSubject
        credential_subject_data = credential['credentialSubject']
        recalculated_merkle_leaves = []
        sorted_keys = sorted(credential_subject_data.keys())
        
        for key in sorted_keys:
            value = credential_subject_data[key]
            leaf_content = {key: value}
            # Assicurati di usare la stessa funzione di canonizzazione dell'Issuer
            leaf_data_str = self._canonical_json_dump(leaf_content)
            
            hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hasher.update(leaf_data_str.encode('utf-8'))
            recalculated_merkle_leaves.append(hasher.finalize())
        
        # print(f"{self.student_name}: Foglie Merkle ricalcolate per {len(recalculated_merkle_leaves)} attributi.")

        # 4. Ricalcola la Merkle Root
        try:
            recalculated_merkle_tree = self._build_merkle_tree(recalculated_merkle_leaves)
            recalculated_merkle_root_bytes = recalculated_merkle_tree[0]
            recalculated_merkle_root_b64 = base64.b64encode(recalculated_merkle_root_bytes).decode('utf-8')
            print(f"{self.student_name}: Merkle Root ricalcolata: {recalculated_merkle_root_b64}")
            
        except Exception as e:
            print(f"{self.student_name}: ERRORE: Impossibile ricalcolare la Merkle Root: {e}")
            return False

        # 5. Confronta la Merkle Root ricalcolata con quella presente nella credenziale
        if recalculated_merkle_root_bytes != merkle_root_from_credential_bytes:
            print(f"{self.student_name}: VERIFICA FALLITA: La Merkle Root ricalcolata NON CORRISPONDE a quella nella credenziale. L'integrità è compromessa!")
            return False
        
        print(f"{self.student_name}: VERIFICA SUPERATA: La Merkle Root ricalcolata CORRISPONDE a quella nella credenziale. Integrità della credenziale OK.")

        # --- Ulteriori Passaggi di Verifica (Cruciali per una verifica completa) ---
        
        # --- Punto 6: Verifica la firma dell'Issuer (Autenticità) ---
        print(f"\n{self.student_name}: Eseguo verifica della firma dell'Issuer.")
        try:
            issuer_did = credential['issuer']['id']
            # Risolvi il DID dell'Issuer per ottenere il DID Document
            issuer_did_document = self.did_manager.resolve_did(issuer_did, 'Issuer')
            # Estrai l'ID della chiave di verifica dalla proof
            verification_method_id = credential['proof']['verificationMethod']
            
            # Estrai la chiave pubblica dell'Issuer dal DID Document
            issuer_public_key = self.did_manager.get_public_key_from_did_document(issuer_did_document, key_id=verification_method_id)
            
            # Recupera la firma dalla credenziale
            signature_b64 = credential['proof']['signatureValue']
            signature_bytes = base64.b64decode(signature_b64)

            # Verifica la firma usando la chiave pubblica dell'Issuer sulla Merkle Root
            if not self._verify_signature(issuer_public_key, merkle_root_from_credential_bytes, signature_bytes):
                print(f"{self.student_name}: VERIFICA FALLITA: La firma dell'Issuer NON è valida. Autenticità compromessa!")
                return False
            
            print(f"{self.student_name}: VERIFICA SUPERATA: Firma dell'Issuer validata. Autenticità OK.")
            return True

        except Exception as e:
            print(f"{self.student_name}: ERRORE: Fallimento durante la verifica della firma dell'Issuer: {e}")
            return False
        
        
        
    # --- Funzione per la Verifica della Firma (utilizzata nel punto 7) ---
    def _verify_signature(self, public_key, signed_data: bytes, signature_bytes: bytes) -> bool:
        """
        Verifica una firma RSA-PSS.
        Questa funzione deve corrispondere all'algoritmo di firma usato dall'Issuer (_sign_data).
        """
        try:
            public_key.verify(
                signature_bytes,
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"  Wallet: ERRORE durante la verifica della firma: {e}")
            return False
        
        
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
        
        return tree 
    
    
    def _canonical_json_dump(self, data):
        # Funzione ricorsiva per creare una stringa JSON canonica per l'hashing
        if isinstance(data, dict):
            return json.dumps({k: self._canonical_json_dump(data[k]) for k in sorted(data.keys())}, separators=(',', ':'))
        elif isinstance(data, list):
            return '[' + ','.join(self._canonical_json_dump(item) for item in data) + ']'
        elif isinstance(data, bool):
            return 'true' if data else 'false'
        elif data is None:
            return 'null'
        elif isinstance(data, (int, float)):
            return str(data)
        else:
            return json.dumps(data) # Per stringhe, per gestire correttamente i caratteri speciali
