class AE:
    def __init__(self, did,contract):
        self.name = 'Ente di Accreditamento'
        self.did = did
        self.contract = contract

    def getDid(self):
        return self.did

    def giveAccreditation(self, target_did, entity_type):
        return self.contract.accredit_entity(caller_did=self.did, target_did = target_did, entity_type = entity_type)