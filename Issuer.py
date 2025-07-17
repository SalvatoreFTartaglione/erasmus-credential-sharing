from DIDManager import DIDManager


class Issuer:
    def __init__(self, name, dlt, ae, credential_registry):
        self.name = name
        self.did = None
        self.dlt = dlt
        self.did_manager = DIDManager(name, dlt, type="Issuer")
        self.ae = ae
        self.public_key = None
        self.did_document = None
        self.entity_type = "Issuer"
        self.isAccredited = False
        self.credential_registry = credential_registry

    def accredit_request(self):
        print(f"Accreditamento dell\'Issuer {self.name}")
        self.did = self.did_manager.generate_did()
        self.public_key = self.did_manager.generate_keys()
        self.did_document = self.did_manager.build_did_document()
        self.isAccredited = self.ae.giveAccreditation(target_did=self.did_document, entity_type=self.entity_type)
        if self.isAccredited:
            print(f"Issuer accreditato con did -> {self.did}")
            return True
        else:
            print('Errore di accreditamento.\nEnte non accreditato.')
            return False

    def release_credential(self, entity_type):
        if self.isAccredited and entity_type == "Student":
            # rilascia una credenziale
            credential_hash = None
            self.credential_registry.register_credential(credential_hash=credential_hash, issuer_did=self.did)


