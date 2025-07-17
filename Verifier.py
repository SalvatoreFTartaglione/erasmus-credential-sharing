from DIDManager import DIDManager

class Verifier:
    
    def __init__(self, name, dlt, ae, did_manager):
        self.name = name
        self.did = None
        self.dlt = dlt
        self.did_manager = did_manager
        self.ae = ae
        self.public_key = None
        self.private_key = None
        self.did_document = None
        self.entity_type = "Verifier"
        self.is_verified = False

    # Request accreditation for the Verifier
    # This method generates a DID, public key, and DID document, then requests accreditation from
    def accredit_request(self):
        print(f"Accreditamento del Verifier {self.name}")
        self.did = self.did_manager.generate_did(self.name)
        self.public_key, self.private_key = self.did_manager.generate_keys()
        self.did_document = self.did_manager.build_did_document(
            did=self.did, public_key=self.public_key, entity_name=self.name
        )
        self.is_verified = self.ae.giveAccreditation(target_did = self.did_document, entity_type = self.entity_type)
        if self.is_verified:
            print(f"Verifier accreditato con did -> {self.did}")
            return True
        else:
            print('Errore di accreditamento.\nEnte non accreditato.')
            return False