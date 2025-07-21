import hashlib
import json
import time

class DLT:
    def __init__(self):
        self.ledger = []  # Simula la blockchain come lista di blocchi
        self.smart_contracts = {}  # Registro di smart contract deployati

    def deploy_contract(self, name, contract):
        self.smart_contracts[name] = contract
        # print(f"[DLT] Smart contract '{name}' deployato.")

    def get_contract(self, name):
        return self.smart_contracts.get(name, None)

    def add_block(self, data):
        previous_hash = self.ledger[-1]['hash'] if self.ledger else '0' * 64
        block = {
            'timestamp': time.time(),
            'data': data,
            'previous_hash': previous_hash,
        }
        block['hash'] = self.hash_block(block)
        self.ledger.append(block)
        # print(f"[DLT] Nuovo blocco aggiunto: hash {block['hash'][:10]}...")

    def hash_block(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def show_ledger(self):
        print("\n[DLT] Stato attuale della blockchain:")
        for idx, block in enumerate(self.ledger):
            print(f"  Block {idx} | Hash: {block['hash'][:10]}... | Data Type: {type(block['data']).__name__}")
