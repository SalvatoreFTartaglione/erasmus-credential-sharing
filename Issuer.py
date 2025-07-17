from DIDManager import DIDManager

class Issuer:
    def __init__(self, name, dlt, ae):
        self.name = name
        self.did = None
        self.dlt = dlt
        self.did_manager = DIDManager(name, dlt, type="Issuer")
        self.ae = ae
        self.public_key = None
        self.did_document = None
        self.entity_type = "Issuer"

    def accredit_request(self):
        print(f"Accreditamento dell\'Issuer {self.name}")
        self.did = self.did_manager.generate_did()
        self.public_key = self.did_manager.generate_keys()
        self.did_document = self.did_manager.build_did_document()
        outcome = self.ae.giveAccereditation(
            target_did= self.did_document,
            entity_type = self.entity_type
        )
        if outcome:
            print(f"Issuer accreditato con did -> {self.did}")
        else:
            print('Errore di accreditamento.\nEnte non accreditato.')