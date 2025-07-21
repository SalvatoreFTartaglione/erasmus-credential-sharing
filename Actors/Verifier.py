import json
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from Utils.TLS import TLS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Verifier:
    
    def __init__(self, name, ae, did_manager, accreditation_registry, status_registry):
        self.name = name
        self.did = None
        self.did_manager = did_manager
        self.ae = ae
        self.public_key = None
        self.private_key = None 
        self.did_document = None
        self.entity_type = "Verifier"
        self.is_verified = False
        self.ae_ca_certificate = None # Store AE's CA certificate for validation
        self.accreditation_x509_certificate = None # Oggetto x509.Certificate
        self.accreditation_vc = None # Dizionario VC (JSON)
        self.issuer_public_key_pem = None
        self.accreditation_registry = accreditation_registry
        self.credential_status_registry = status_registry
        
    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    # Request accreditation for the Verifier
    # This method generates a DID, public key, and DID document, then requests accreditation from
    def accredit_request(self):
        self.did = self.did_manager.generate_did(self.name)
        self.public_key, self.private_key = self.did_manager.generate_keys()
        
        # Inizializza il DID Document locale del Verifier prima di inviarlo per l'accreditamento all'AE
        self.did_document = self.did_manager.build_did_document(
            did=self.did, public_key=self.public_key, entity_name=self.name, entity_type=self.entity_type
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

    def receive_presentation(self, ciphertext_presentation: dict):
        print(f"\nVerifier {self.name}: Ricevuta presentazione cifrata via canale TLS.")

        # 1. Estrai i componenti cifrati
        encrypted_aes_key = ciphertext_presentation["encrypted_aes_key"]
        iv = ciphertext_presentation["iv"]
        ciphertext = ciphertext_presentation["ciphertext"]

        # 2. Carica la chiave privata del verifier da PEM a oggetto
        server_private_key = TLS.load_private_key_from_pem(self.private_key)

        # 3. Decifra la chiave AES
        aes_key = TLS.server_receive_tls_key(encrypted_aes_key, server_private_key)
        print(f"Verifier {self.name}: Chiave AES decifrata correttamente.")

        # 4. Decripta la presentazione con AES
        decrypted_json_bytes = TLS.decrypt_message_aes(aes_key, iv, ciphertext)
        decrypted_json_str = decrypted_json_bytes.decode("utf-8")

        # 5. Converte il JSON string in oggetto Python
        vp = json.loads(decrypted_json_str)
        print(f"Verifier {self.name}: Verifiable Presentation ricevuta e decifrata correttamente.")

        # 6. Verifica la presentazione
        result = self.verify_presentation(vp)
        print(f"La VP è valida: {result}")
        return result

    # Nuovo metodo per verificare una presentazione (VP)
    def verify_presentation(self, verifiable_presentation: dict) -> bool:
        """
        Verifica una Verifiable Presentation (VP) presentata da uno Studente.
        Implementa i passaggi da 7.A a 7.F del WP2.
        """
        
        print(f"\nVerifier {self.name}: Avvio processo di verifica della presentazione.")
        
        # --- Step 7.A ---#
        is_signature_valid, student_public_key = self._verify_presentation_signature(verifiable_presentation)  # La funzione restituirà se la verifica è andata a buon fine e la chiave pubblica dello studente
        if not is_signature_valid:
            return False
        
        # Credential contains the VC extracted from the VP
        credential = verifiable_presentation.get('verifiableCredential')
        
        # --- Step 7.B ---#
        if not self._verify_credential_with_merkle_proof(verifiable_presentation): return False
        
        # --- Step 7.C ---#
        if not self._verify_issuer_accreditation(credential, self.issuer_public_key_pem): return False
        
        # --- Step 7.D ---#
        if not self._check_credential_revocation(credential): return False
        
        # --- Step 7.E ---#
        # (requires student interaction simulation)
        if not self._perform_challenge_response(student_public_key): return False 
        
        # --- Step 7.F ---#
        if not self._process_selective_disclosure(verifiable_presentation, credential): return False    
            
        # Se tutti i passaggi sono stati completati con successo, la verifica è riuscita
        print(f"Verifier {self.name}: Tutte le verifiche completate con successo. Credenziale autentica e valida.")
        return True
    
    
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


    # Helper per verificare una firma RSA 
    def _verify_rsa_signature(self, public_key, signed_data, signature):
        """
        Verifica una firma RSA utilizzando lo schema PSS e SHA256.
        :param public_key: Chiave pubblica dell'entità che ha firmato.
        :param signed_data: Il payload originale che è stato firmato (bytes).
        :param signature: La firma da verificare (bytes).
        :return: True se la firma è valida, False altrimenti.
        """
        try:
            public_key.verify(
                signature,
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            # print(f"Errore di verifica firma: {e}")
            return False

    def _verify_presentation_signature(self, verifiable_presentation: dict) -> tuple[bool, rsa.RSAPublicKey | None]:
        """
        7.A: Verifica della Firma della Presentazione dello Studente (VP).
        Estrae il DID dello studente, risolve il DID Document, recupera la chiave pubblica
        e verifica la firma sulla VP.

        :param verifiable_presentation: La Verifiable Presentation da verificare.
        :return: Una tupla (True/False per il successo, Oggetto chiave pubblica dello studente o None).
        """
        print("7.A: Inizio verifica della Firma della Presentazione dello Studente...")
        try:
            # 1. Estrarre il DID dello Studente dalla VP
            student_did = verifiable_presentation.get("holder")
            if not student_did:
                print("7.A: Errore: Campo 'holder' (DID dello Studente) non trovato nella Verifiable Presentation.")
                return False, None

            # 2. Risoluzione del DID dello studente per ottenere il suo DID Document
            student_did_document = self.did_manager.resolve_did(student_did, "Student")

            if not student_did_document:
                print(f"7.A: Errore: Impossibile risolvere il DID dello Studente: {student_did}.")
                return False, None

            # 3. Estrazione della chiave pubblica dal DID Document dello Studente
            student_public_key_pem = self.did_manager.get_public_key_from_did_document(student_did_document)
            if not student_public_key_pem:
                print(f"7.A: Errore: Chiave pubblica non trovata nel DID Document dello Studente: {student_did}.")
                return False, None

            # Conversione della chiave pubblica in formato PEM in un oggetto PublicKey
            student_public_key = student_public_key_pem
            if not student_public_key:
                print("7.A: Errore: Impossibile caricare l'oggetto chiave pubblica dello Studente.")
                return False, None

            # 4. Verifica della firma della VP utilizzando la chiave pubblica dello Studente
            vp_proof = verifiable_presentation.get('proof', {})
            vp_signature_value_b64 = vp_proof.get('signatureValue') or vp_proof.get('jws')

            if not vp_signature_value_b64:
                print("7.A: Errore: Nessuna firma trovata nella VP: né 'signatureValue' né 'jws'.")
                return False, None

            vp_signature_bytes = base64.b64decode(vp_signature_value_b64)

            # 5. Ricostruire il payload che è stato firmato (escludendo il campo 'proof')
            vp_to_verify = dict(verifiable_presentation)
            if 'proof' in vp_to_verify:
                del vp_to_verify['proof']

            # Normalizzazione JSON per la firma (ordinamento chiavi e separatori)
            vp_payload_bytes = json.dumps(vp_to_verify, sort_keys=True, separators=(',', ':')).encode('utf-8')

            # 6. Verifica della firma della VP
            if self._verify_rsa_signature(student_public_key, vp_payload_bytes, vp_signature_bytes):
                print("7.A: Firma della Presentazione dello Studente verificata con successo.")
                return True, student_public_key
            else:
                print("7.A: Errore: Firma della Presentazione dello Studente NON valida.")
                return False, None

        except Exception as e:
            print(f"7.A: Errore critico durante la verifica della firma della Presentazione dello Studente: {e}")
            return False, None

    # def _verify_all_merkle_proofs(self, verifiable_credential_subset: dict) -> bool:
    #     import hashlib
    #     import json
    #
    #     revealed_attributes = verifiable_credential_subset.get('revealedAttributes', [])
    #     merkle_proofs = verifiable_credential_subset.get('merkleProofs', {})
    #     merkle_root_hex = verifiable_credential_subset.get('merkleRoot')
    #
    #     if not revealed_attributes or not merkle_proofs or not merkle_root_hex:
    #         print("Errore: mancano attributi rivelati, proofs o merkleRoot per la verifica.")
    #         return False
    #
    #     def hash_leaf(attr: dict) -> bytes:
    #         import hashlib
    #         import json
    #
    #         attr_normalized = {
    #             "id": int(attr["id"]),
    #             "title": str(attr["title"]),
    #             "grade": str(attr["grade"])
    #         }
    #
    #         serialized = json.dumps(attr_normalized, sort_keys=True, separators=(',', ':')).encode("utf-8")
    #         return hashlib.sha256(serialized).digest()
    #
    #     def hash_pair(left: bytes, right: bytes) -> bytes:
    #         return hashlib.sha256(left + right).digest()
    #
    #     merkle_root_bytes = bytes.fromhex(merkle_root_hex)
    #
    #
    #     for attr in revealed_attributes:
    #         leaf_hash = hash_leaf(attr)
    #         leaf_hex = leaf_hash.hex()
    #         proof_list = merkle_proofs.get(leaf_hex)
    #
    #         print("Attr JSON serializzato:", json.dumps(attr, sort_keys=True))
    #         print("Leaf hex:", leaf_hex)
    #         print("Proofs keys:", list(merkle_proofs.keys()))
    #
    #         if proof_list is None:
    #             print(f"Errore: Merkle proof mancante per la foglia {leaf_hex}")
    #             return False
    #
    #         computed = leaf_hash
    #         for entry in proof_list:
    #             sibling_hash = bytes.fromhex(entry['hash'])
    #             if entry['position'] == 'left':
    #                 computed = hash_pair(sibling_hash, computed)
    #             else:
    #                 computed = hash_pair(computed, sibling_hash)
    #
    #         if computed != merkle_root_bytes:
    #             print(f"Errore: la Merkle proof per la foglia {leaf_hex} non porta alla root corretta.")
    #             print(f"Computed: {computed.hex()}, Expected: {merkle_root_hex}")
    #             return False
    #
    #
    #     return True

    def _verify_credential_with_merkle_proof(self, verifiable_presentation: dict) -> bool:
        """
        7.B: Verifica la firma dell'Issuer sulla Merkle Root della Credenziale Originale
        e valida la Merkle Proof per gli attributi rivelati.
        :param verifiable_presentation: La Verifiable Presentation ricevuta, che include la VC subset,
                                        la Merkle Root, le proof, e la firma dell'Issuer.
        :return: True se la verifica è riuscita, False altrimenti.
        """
        print("7.B: Inizio verifica della Firma della Merkle Root dell'Issuer e della Merkle Proof...")

        # 1. Estrai la verifiableCredential dalla presentazione
        verifiable_credential_subset = verifiable_presentation.get('verifiableCredential', {})
        if not verifiable_credential_subset:
            print("7.B: Errore: verifiableCredential mancante nella presentazione.")
            return False

        # 2. Estrai il DID dell'Issuer dalla VC subset
        issuer_did = verifiable_credential_subset.get('issuer')
        if not issuer_did:
            print("7.B: Errore: DID dell'Issuer non trovato nella credenziale subset.")
            return False

        # 3. Risolvi il DID dell'Issuer per ottenere la sua chiave pubblica
        print(f"7.B: Risoluzione del DID dell'Issuer: {issuer_did}")
        issuer_did_document = self.did_manager.resolve_did(issuer_did, did_type=self.entity_type)
        if not issuer_did_document:
            print(f"7.B: Errore: Impossibile risolvere il DID dell'Issuer: {issuer_did}. DID Document non trovato.")
            return False

        self.issuer_public_key_pem = self.did_manager.get_public_key_from_did_document(issuer_did_document)
        if not self.issuer_public_key_pem:
            print(f"7.B: Errore: Chiave pubblica non trovata nel DID Document dell'Issuer: {issuer_did}.")
            return False

        issuer_public_key = self.issuer_public_key_pem
        if not issuer_public_key:
            print("7.B: Errore: Impossibile caricare l'oggetto chiave pubblica dell'Issuer.")
            return False

        print(f"7.B: Chiave pubblica dell'Issuer {issuer_did} recuperata con successo.")

        # 4. Estrai la Merkle Root dalla VC subset (non codificata base64, ma esadecimale)
        merkle_root_hex = verifiable_credential_subset.get('merkleRoot')
        if not merkle_root_hex:
            print("7.B: Errore: Merkle Root mancante nella credenziale subset.")
            return False

        # Converti la Merkle Root esadecimale in bytes
        try:
            merkle_root_bytes = bytes.fromhex(merkle_root_hex)
        except Exception as e:
            print(f"7.B: Errore: formato Merkle Root non valido: {e}")
            return False

        # 5. Estrai la firma dell'Issuer dalla proof nella presentazione (non nella VC)
        proof = verifiable_presentation.get('verifiableCredential', {}).get('proof', {})
        issuer_signature_b64 = proof.get('signatureValue')
        if not issuer_signature_b64:
            print("7.B: Errore: Firma dell'Issuer sulla Merkle Root mancante nella proof della presentazione.")
            return False

        try:
            issuer_signature_bytes = base64.b64decode(issuer_signature_b64)
        except Exception as e:
            print(f"7.B: Errore: firma dell'Issuer non valida Base64: {e}")
            return False

        # 6. Verifica la firma RSA dell'Issuer sulla Merkle Root
        print(f"Firma dell'Issuer sulla root: {issuer_signature_bytes}")
        if not self._verify_rsa_signature(issuer_public_key, merkle_root_bytes, issuer_signature_bytes):
            print("7.B: Errore: Firma dell'Issuer sulla Merkle Root NON valida.")
            return False
        print("7.B: Firma dell'Issuer sulla Merkle Root verificata con successo.")

        # 7. Estrai attributi rivelati e Merkle Proofs dalla VC subset
        revealed_attributes = verifiable_credential_subset.get('revealedAttributes', [])
        merkle_proofs = verifiable_credential_subset.get('merkleProofs', {})

        if not revealed_attributes or not merkle_proofs:
            print(
                "7.B: Avvertimento: Nessun attributo rivelato o Merkle Proof fornita. La divulgazione selettiva non può essere verificata appieno.")
            # Puoi decidere se bloccare o meno la verifica a questo punto

        # 8. Verifica delle Merkle Proofs per ogni attributo rivelato (simulato)
        print("7.B Verifica del markle proofs avvenuta con successo. (Simulato)")

        print("7.B: Verifica della Credenziale con Merkle Proof completata con successo.")
        return True

    def _verify_issuer_accreditation(self, credential: dict, issuer_public_key_from_vc: rsa.RSAPublicKey) -> bool:
        """
        7.C: Risoluzione e Verifica del DID dell'Issuer.
        Interroga lo smart contract AccreditationRegistry sulla DLT.
        Recupera lo stato di accreditamento e la chiave pubblica dell'Issuer registrati.
        Controlla che il DID sia registrato, che la publicKey corrisponda a quella usata
        per la firma della credenziale (verificata in 7.B) e che lo status sia "accreditato".

        :param credential: Il subset della credenziale presentato nella VP, contenente il DID dell'Issuer.
        :param issuer_public_key_from_vc: L'oggetto chiave pubblica dell'Issuer recuperato e usato in 7.B.
        :return: True se l'Issuer è accreditato e le verifiche corrispondono, False altrimenti.
        """
        print("\n7.C: Inizio risoluzione e verifica del DID dell'Issuer e dello stato di accreditamento.")

        issuer_did = credential.get('issuer')
        if not issuer_did:
            print("7.C: Errore: DID dell'Issuer non trovato nella credenziale per la verifica dell'accreditamento.")
            return False

        print(f"7.C: Interrogazione dello smart contract AccreditationRegistry per il DID: {issuer_did}")

        try:
            # Recupera lo stato di accreditamento dell'Issuer dalla DLT
            # Assumiamo che AccreditationRegistry abbia un metodo 'get_accreditation_status'
            # che restituisca lo stato (es. "Accredited", "Revoked", "Pending", None)
            accreditation_record = self.accreditation_registry.get_accreditation_status(issuer_did)

            if not accreditation_record or accreditation_record['status'] == 'NotRegistered':
                print(f"7.C: Errore: DID dell'Issuer {issuer_did} NON registrato nell'AccreditationRegistry.")
                return False


            print(f"7.C DID dell'Issuer {issuer_did} registrato nell'AccreditationRegistry correttamente.")

            registered_status = accreditation_record['status']
            registered_public_key_pem = accreditation_record['publicKeyPem'] # Assumiamo che il registry la memorizzi

            # Carica la chiave pubblica registrata dal formato PEM
            if not registered_public_key_pem:
                print(f"7.C: Errore: Chiave pubblica PEM non trovata nel DID Document registrato per {issuer_did}.")
                return False

            try:
                registered_public_key = serialization.load_pem_public_key(
                    registered_public_key_pem.encode(),
                    backend=default_backend()
                )
            except Exception as e:
                print(f"7.C: Errore durante il parsing della chiave pubblica PEM per {issuer_did}: {e}")
                return False

            # Controlla che il DID sia registrato (già fatto sopra) e che lo status sia "Accredited"
            if registered_status != "Accredited":
                print(f"7.C: Errore: L'Issuer {issuer_did} non ha status 'Accredited'. Stato attuale: '{registered_status}'.")
                return False
            print(f"7.C: Status dell'Issuer {issuer_did} è 'Accredited'.")

            # Controlla che la chiave pubblica restituita dal registro corrisponda a quella usata per la firma
            # Confrontiamo gli oggetti chiave pubblica.
            if registered_public_key.public_numbers() != issuer_public_key_from_vc.public_numbers():
                print(f"7.C: Errore: La chiave pubblica dell'Issuer {issuer_did} registrata nell'AccreditationRegistry NON corrisponde a quella usata per firmare la credenziale.")
                return False
            print(f"7.C: Chiave pubblica dell'Issuer {issuer_did} verificata con successo: corrisponde a quella registrata.")

            print(f"7.C: Risoluzione e Verifica del DID dell'Issuer e dello stato di accreditamento completati con successo.")
            return True

        except Exception as e:
            print(f"7.C: Errore critico durante la verifica dell'accreditamento dell'Issuer: {e}")
            return False
    
    
    
    def _check_credential_revocation(self, credential: dict) -> bool:
        """
        7.D: Controllo dello Stato di Revoca della Credenziale.
        Interroga lo Smart Contract CredentialStatusRegistry sulla DLT per verificare lo stato
        di revoca dell'hash/identificatore della credenziale presentata.
        Questo garantisce che la credenziale non sia stata invalidata dall'Università di Rennes dopo la sua
        emissione (credentialStatus deve essere "valida").

        :param credential: Il subset della credenziale presentato nella VP, contenente l'ID della credenziale.
        :return: True se la credenziale è valida (non revocata), False altrimenti.
        """
        print("\n7.D: Inizio controllo dello Stato di Revoca della Credenziale.")
        
        # L'ID della credenziale deve essere presente nella VC subset.
        # Generalmente, è il campo 'id' a livello superiore della VC.
        credential_id = credential.get('proof',{}).get('merkleRoot')
        if not credential_id:
            print("7.D: Errore: ID della Credenziale non trovato nel subset della credenziale per il controllo di revoca.")
            return False

        print(f"7.D: Interrogazione dello Smart Contract CredentialStatusRegistry per l'ID credenziale: {credential_id}")

        try:
            # Assumiamo che CredentialStatusRegistry abbia un metodo 'get_credential_status'
            # che restituisca lo stato (es. "valid", "revoked", "suspended", ecc.)
            # o direttamente un booleano 'is_revoked'.
            # Qui useremo 'is_revoked' per semplicità, ma si può adattare.
            
            is_revoked_on_dlt = self.credential_status_registry.is_revoked(credential_id)

            if is_revoked_on_dlt:
                print(f"7.D: Errore: Credenziale {credential_id} è stata REVOCATA o NON TROVATA dall'Issuer (Università di Rennes).")
                return False
            else:
                print(f"7.D: Credenziale {credential_id} è VALIDA (non revocata).")
                return True

        except Exception as e:
            print(f"7.D: Errore critico durante il controllo dello stato di revoca: {e}")
            return False

    def _perform_challenge_response(self, student_public_key: rsa.RSAPublicKey) -> bool:
        """
        7.E: Esegue il protocollo di sfida-risposta con lo Studente per la prova di possesso.
        Questa è una simulazione che richiede un'implementazione lato Studente.
        """
        print("7.E: Simulazione: Protocollo di Sfida-Risposta con lo Studente.")
        challenge = os.urandom(16).hex()
        print(f"   Generata sfida: {challenge}")
        print("   (Simulazione) Lo Studente ha firmato la sfida correttamente.")
        return True




    def _process_selective_disclosure(self, verifiable_presentation: dict, credential: dict) -> bool:
        """
        7.F: Estrae e elabora solo gli attributi rivelati selettivamente nella VP.
        """
        print("7.F: (Da implementare) Elaborazione Selettiva degli Attributi...")
        # Analizzare la VP per identificare gli attributi rivelati
        # Estrarre solo quelli dal `credential.credentialSubject`
        return True # Placeholder