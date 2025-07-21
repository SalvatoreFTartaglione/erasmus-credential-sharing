import uuid
from Utils.TLS import TLS
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import time
import os


class Wallet:
    def __init__(self, student_name, student_did, student_did_document, student_public_key, student_private_key, issuer, verifier, ae, accreditation_registry, did_manager, credential_status_registry):
        self.entity_name = "Wallet_" + str(uuid.uuid4())
        self.credential = None
        self.presentation = None
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
        self.credential_status_registry = credential_status_registry


    def get_student_did(self):
        return self.student_did


    def get_student_did_document(self):
        return self.student_did_document

    def get_credential(self):
        return self.credential

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

    def set_credential(self, credential):
        self.credential = credential

    def send_vp_to_Verifier(self, lista_id, student_private_key_pem, student_public_key_pem, verifier_public_key_pem):
        print(f"Sono il wallet di {self.student_did} e genero una VP...")
        student_private_key = serialization.load_pem_private_key(
            student_private_key_pem.encode(),
            password=None
        )
        self.presentation = self._create_vp(self.student_did, self.credential,lista_id,student_private_key)
        if self.presentation is None:
            print("Errore nella creazione della presentazione")
        else:
            print(f"Presentation creata con successo")
            print("Invio la VP all'Università di Salerno")

            # Serializza la VP in JSON e la converte in bytes
            vp_json = json.dumps(self.presentation, ensure_ascii=False).encode("utf-8")

            # Carica le chiavi del client (studente) e del server (verifier)
            client_private_key = TLS.load_private_key_from_pem(student_private_key_pem)
            client_public_key = TLS.load_public_key_from_pem(student_public_key_pem)
            verifier_public_key = TLS.load_public_key_from_pem(verifier_public_key_pem)

            # 1. Simula l'handshake TLS per condividere la chiave AES
            encrypted_aes_key, original_aes_key = TLS.simulate_tls_handshake(
                client_private_key, client_public_key, verifier_public_key
            )

            # 2. Cifra il messaggio (VP) con la chiave AES
            iv, ciphertext = TLS.encrypt_message_aes(original_aes_key, vp_json)

            # 3. Simula invio al server (ritorno di tutti i dati per test)
            print("VP cifrata e pronta per l'invio al verifier.")

            self.verifier.receive_presentation({
                "encrypted_aes_key": encrypted_aes_key,
                "iv": iv,
                "ciphertext": ciphertext
            })

            return {
                "encrypted_aes_key": encrypted_aes_key,
                "iv": iv,
                "ciphertext": ciphertext
            }

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
            print(f"[WALLET] Errore: Impossibile risolvere il DID dell'Issuer: {issuer_did}. Richiesta abortita.")
            return False

        # 2. Recuperare il Certificato X.509 dell'Issuer dal suo DID Document
        issuer_x509_cert = self.did_manager.get_x509_certificate_from_did_document(issuer_did_document)
        if not issuer_x509_cert:
            print(f"[WALLET] Errore: Certificato X.509 dell'Issuer {issuer_did} non trovato nel DID Document. Richiesta abortita.")
            return False
        
        # 3. Verificare il certificato X.509 dell'Issuer usando il certificato CA dell'Accreditation Authority
        # Il certificato CA dell'AE è un attributo dell'istanza dell'AE, che è passato al Wallet.
        if not self.ae.ca_certificate:
            print("[WALLET] Errore: Certificato CA dell'Accreditation Authority non disponibile. Impossibile verificare X.509.")
            return False

        if not self._verify_x509_certificate(issuer_x509_cert, self.ae.ca_certificate):
            print(f"[WALLET] Errore: Certificato X.509 dell'Issuer {issuer_did} NON valido o non firmato dalla CA dell'AE. Richiesta abortita.")
            return False
        
        # 4. Interrogare lo smart contract AccreditationRegistry sulla DLT
        # Questo è un controllo aggiuntivo per assicurarsi che l'Issuer sia registrato come "Accredited" sulla DLT.
        print(f"Wallet: Interrogazione AccreditationRegistry sulla DLT per lo stato di {issuer_did}...")
        accreditation_status = self.accreditation_registry.get_accreditation_status(issuer_did)

        if not accreditation_status:
            print(f"[WALLET] Errore: Issuer {issuer_did} non trovato o non 'Accredited' nell'AccreditationRegistry. Richiesta abortita.")
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

        # 6. Verifica la firma dell'Issuer (Autenticità) ---
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

        # --- Punto 7: Verifica della validità della credenziale --- #
        print(f"\n{self.student_name}: Eseguo verifica della validità della credenziale.")
        if not self._verify_credential_status(credential):
            print(f"{self.student_name}: VERIFICA FALLITA: La credenziale rilasciata dall'issuer NON è valida")
            return False
        print(f"{self.student_name}: VERIFICA SUPERATA: FLa credenziale rilasciata dall'issuer è valida.")

        return True




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

    def _build_merkle_tree_vp(self, leaves):
        """
        Costruisce un Merkle Tree come lista di livelli:
        ogni livello è una lista di hash byte
        leaves: lista di hash byte (es. [b'\x12\x34...', b'\xab\xcd...'])
        """
        if not leaves:
            return []

        current_level = leaves.copy()

        tree_levels = [current_level]  # livello 0: foglie

        while len(current_level) > 1:
            # se dispari, duplica l'ultimo
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i + 1]
                new_hash = hashlib.sha256(combined).digest()
                next_level.append(new_hash)

            tree_levels.append(next_level)
            current_level = next_level

        return tree_levels

    def _create_vp(self, student_did, credential, lista_id, student_private_key):
        credential_subject = credential.get("credentialSubject", {})

        # 1. Selezione attributi
        revealed_attributes = []
        agreed_courses = credential_subject.get("learningAgreement", {}).get("agreedCourses", [])
        optional_courses = credential_subject.get("optionalExperience", {}).get("optionalCourses", [])

        all_courses = agreed_courses + optional_courses

        for course in all_courses:
            course_id = course.get("id")
            if course_id is not None and int(course_id) in lista_id:
                revealed_attributes.append({
                    "id": course_id,
                    "title": course.get("title"),
                    "grade": course.get("grade")
                })

        if not revealed_attributes:
            print("Errore: nessun attributo selezionato per la presentazione. Lista vuota.")
            return None

        # 2. Hash foglie (in byte)
        def hash_leaf(attr: dict) -> bytes:
            # Forza i tipi e garantisce consistenza tra creazione e verifica
            attr_normalized = {
                "id": int(attr["id"]),
                "title": str(attr["title"]),
                "grade": str(attr["grade"])
            }

            # Serializzazione deterministica e compatta (senza spazi inutili)
            serialized = json.dumps(attr_normalized, sort_keys=True, separators=(',', ':')).encode("utf-8")

            return hashlib.sha256(serialized).digest()

        # Recupera tutti i corsi dalla VC
        all_courses = agreed_courses + optional_courses

        # Hash di tutte le foglie (usando stesso metodo dell’issuer)
        full_leaves = [hash_leaf(course) for course in all_courses]

        # Costruisci l'intero albero
        merkle_tree = self._build_merkle_tree_vp(full_leaves)

        # Trova proof solo per gli attributi rivelati
        def find_index_by_id(courses, course_id):
            for idx, course in enumerate(courses):
                if course["id"] == course_id:
                    return idx
            return -1

        revealed_indices = [find_index_by_id(all_courses, attr["id"]) for attr in revealed_attributes]
        revealed_hashes = [full_leaves[i] for i in revealed_indices]

        if not merkle_tree or not merkle_tree[-1]:
            print("Errore: Merkle Tree vuoto o costruito in modo errato.")
            return None

        merkle_root = merkle_tree[-1][0]  # radice (byte)

        print("Merkle tree livelli:")
        for i, level in enumerate(merkle_tree):
            print(f"Livello {i}: {[h.hex() for h in level]}")

        print("Radice Merkle calcolata:", merkle_root.hex())
        original_merkle_root = credential.get("merkleRoot", {})
        merkle_root_bytes = base64.b64decode(original_merkle_root)
        original_merkle_root_hex = merkle_root_bytes.hex()
        print("Radice Merkle originale:", original_merkle_root_hex)

        def get_proofs(leaves, tree_levels):
            proofs = {}
            for idx, leaf in enumerate(leaves):
                proof = []
                index = idx
                for level in tree_levels[:-1]:
                    sibling_index = index ^ 1
                    if sibling_index < len(level):
                        sibling = level[sibling_index]
                        position = 'left' if sibling_index < index else 'right'
                        proof.append({
                            'position': position,
                            'hash': sibling.hex()
                        })
                    index //= 2
                proofs[leaf.hex()] = proof
            return proofs

        merkle_proofs = get_proofs(revealed_hashes, merkle_tree)

        issuer_did = credential.get("issuer", {}).get("id", "did:example:issuer-unisa")
        issuer_proof = credential.get("proof", {})
        original_merkle_root = credential.get("merkleRoot", {})
        merkle_root_bytes = base64.b64decode(original_merkle_root)
        original_merkle_root_hex = merkle_root_bytes.hex()
        credential_id = credential.get("id")

        vp = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": {
                "revealedAttributes": revealed_attributes,
                "merkleRoot": original_merkle_root_hex,
                "merkleProofs": merkle_proofs,
                "issuer": issuer_did,
                "proof": issuer_proof,
                "id": credential_id
            },
            "holder": student_did,
            "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # Firma della VP con la chiave privata dello studente
        def sign_presentation_rsa(presentation_dict, private_key):
            presentation_copy = dict(presentation_dict)
            presentation_copy.pop("proof", None)
            payload = json.dumps(presentation_copy, sort_keys=True, separators=(',', ':')).encode("utf-8")
            signature = private_key.sign(
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode("utf-8")

        vp["proof"] = {
            "type": "RSASignature2024",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{student_did}#keys-1",
            "signatureValue": sign_presentation_rsa(vp, student_private_key)

        }

        # Salvataggio su file JSON
        os.makedirs("VPs", exist_ok=True)
        filename = os.path.join("VPs", f"vp_{student_did.split(':')[-1]}.json")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(vp, f, indent=4, ensure_ascii=False)

        return vp


    def _verify_credential_status(self, credential: dict) -> bool:
        """
        Recupera lo stato di una credenziale dal CredentialStatusRegistry
        e controlla che il suo status sia 'Valid'.
        :param credential: Il dizionario completo della Verifiable Credential.
        :return: True se lo stato della credenziale è 'Valid', False altrimenti.
        """
        # La Merkle Root è l'identificatore della credenziale registrato nel CredentialStatusRegistry.
        credential_hash = credential.get('merkleRoot')

        if not credential_hash:
            print("[Verifica Stato Credenziale] ERRORE: Merkle Root non trovata nella credenziale. Impossibile verificare lo stato.")
            return False

        is_valid = self.credential_status_registry.is_credential_valid(credential_hash)

        return is_valid