from DLT.AccreditationRegistry import AccreditationRegistry
from DLT.DLT import DLT
from Issuer import Issuer
from AE import AE

dlt = DLT()
authority_did = "did:entediaccreditamento:0001"
registry = AccreditationRegistry(accrediting_authority_did=authority_did)
dlt.deploy_contract(name="AccreditationRegistry", contract=registry)
ae = AE(authority_did,registry)


print("\n##########################################################")
print("\n#  Inizializzazione dell\'Issuer (Università di Rennes)  #")
print("\n##########################################################")
# Logica che accredita l'issuer
issuer = Issuer("Università di Rennes", dlt)
issuer.accredit_request()
print("\n##########################################################")
print("\n#          Issuer accreditato con successo               #")
print("\n##########################################################")
print('\n')