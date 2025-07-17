from DIDManager import DIDManager

class Verifier:
    
    def __init__(self, name, dlt, ae):
        self.name = name
        self.did = None
        self.dlt = dlt
        self.did_manager = DIDManager(name, dlt, type="Verifier")
        self.ae = ae
        self.public_key = None
        self.did_document = None
        self.entity_type = "Verifier"

    # Request accreditation for the Verifier
    # This method generates a DID, public key, and DID document, then requests accreditation from
    def accredit_request(self):
        print(f"Accreditamento del Verifier {self.name}")
        self.did = self.did_manager.generate_did()
        self.public_key = self.did_manager.generate_keys()
        self.did_document = self.did_manager.build_did_document()
        outcome = self.ae.giveAccreditation(target_did = self.did_document, entity_type = self.entity_type)
        if outcome:
            print(f"Verifier accreditato con did -> {self.did}")
            return True
        else:
            print('Errore di accreditamento.\nEnte non accreditato.')
            return False