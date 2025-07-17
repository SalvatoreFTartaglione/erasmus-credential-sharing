from DIDManager import DIDManager

class Issuer:
    def __init__(self, name):
        self.name = name
        self.did = DIDManager(name)
        self.wallet = None

    def accredit(self):
        print(f"Accreditamento dell'Issuer {self.name}")
        self.did = self.did.generate_did()
        self.wallet = self.load_wallet()
        print(f"Issuer accreditato con did -> {self.did}")

    def load_wallet(self):
        return {"private_key": "privkey", "public_key": "pubkey"}

    def register_on_blockchain(self):
        # Placeholder per interazione con la blockchain
        print("Registrazione DID sulla blockchain (simulata).")
