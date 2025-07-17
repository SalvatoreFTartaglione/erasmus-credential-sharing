from DIDManager import DIDManager
from DLT.AccreditationRegistry import AccreditationRegistry
from DLT.CredentialStatusRegistry import CredentialStatusRegistry
from DLT.DLT import DLT
from Issuer import Issuer
from Verifier import Verifier
from AE import AE


def init_actors():
    """
    Initialize the actors in the system.
    """
    # init DLT
    print("\n##########################################################")
    print("\n#              Inizializzazione del DLT                  #")
    print("\n##########################################################")
    dlt = DLT()
    did_manager = DIDManager(dlt=dlt)

    # Deploy the Accreditation Registry contract
    print("\n##########################################################")
    print("\n#  Deploy del contratto AccreditationRegistry sul DLT    #")
    print("\n##########################################################")
    authority_did = "did:entediaccreditamento:0001"
    accreditation_registry = AccreditationRegistry(accrediting_authority_did=authority_did, dlt=dlt)
    dlt.deploy_contract(name="AccreditationRegistry", contract=accreditation_registry)

    # Deploy the Accreditation Registry contract
    print("\n#############################################################")
    print("\n#  Deploy del contratto CredentialStatusRegistry sul DLT    #")
    print("\n#############################################################")
    credential_status_registry = CredentialStatusRegistry(dlt=dlt)
    dlt.deploy_contract(name = "CredentialStatusRegistry", contract = credential_status_registry)


    # Initialize the AE (Accreditation Entity)
    print("\n##########################################################")
    print("\n#  Inizializzazione dell\'Accreditation Entity (AE)      #")
    print("\n##########################################################")
    ae = AE(authority_did, accreditation_registry)


    # init Issuer
    print("\n##########################################################")
    print("\n#  Inizializzazione dell\'Issuer (Università di Rennes)  #")
    print("\n##########################################################")

    # Logica che accredita l'issuer
    issuer = Issuer("Università di Rennes\n\n", dlt, ae, credential_status_registry, did_manager)
    if issuer.accredit_request():
        print("\n##########################################################")
        print("\n#          Issuer accreditato con successo               #")
        print("\n##########################################################")
        print('\n')
    else:
        print("\n##########################################################")
        print("\n#          Issuer non accreditato                         #")
        print("\n##########################################################")
        print('\n')

    # init verifier
    print("\n##########################################################")
    print("\n# Inizializzazione dell\'Verifier (Università di Salerno)#")
    print("\n##########################################################")
    verifier = Verifier("Università di Salerno\n\n", dlt, ae, did_manager=did_manager)

    # Logica che accredita il Verifier
    if verifier.accredit_request():
        print("\n##########################################################")
        print("\n#          Verifier accreditato con successo             #")
        print("\n##########################################################")
        print('\n')
    else:
        print("\n##########################################################")
        print("\n#          Verifier non accreditato                       #")
        print("\n##########################################################")
        print('\n')
    # Return the initialized actors
    return {
        "dlt": dlt,
        "accreditation_registry": accreditation_registry,
        #"credential_status_registry": credential_status_registry,
        "ae": ae,
        "issuer": issuer,
        "verifier": verifier,
        #"student": student,
    }



if __name__ == "__main__":

    actors = init_actors()