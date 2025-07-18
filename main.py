from DIDManager import DIDManager
from DLT.AccreditationRegistry import AccreditationRegistry
from DLT.CredentialStatusRegistry import CredentialStatusRegistry
from DLT.DLT import DLT
from Issuer import Issuer
from Verifier import Verifier
from AE import AE


def init_actors():
    """
    Initializes the actors in the system.
    """

    ###############################
    #       INITIALIZE DLT        #
    ###############################
    print("\n##########################################################")
    print("\n#              Inizializzazione del DLT                  #")
    print("\n##########################################################")
    dlt = DLT()
    # Initialize the DID Manager with the DLT instance
    did_manager = DIDManager(dlt=dlt)


    ###############################
    #  SMART CONTRACTS DEPLOYMENT #
    ###############################
    # Deploy the Accreditation Registry contract
    print("\n\n\n##########################################################")
    print("\n#  Deploy del contratto AccreditationRegistry sul DLT    #")
    print("\n##########################################################")
    accreditation_registry = AccreditationRegistry(dlt=dlt)
    dlt.deploy_contract(name="AccreditationRegistry", contract=accreditation_registry)

    # Deploy the Accreditation Registry contract
    print("\n\n\n#############################################################")
    print("\n#  Deploy del contratto CredentialStatusRegistry sul DLT    #")
    print("\n#############################################################")
    credential_status_registry = CredentialStatusRegistry(dlt=dlt)
    dlt.deploy_contract(name = "CredentialStatusRegistry", contract = credential_status_registry)

    ###############################
    #      INIT SYSTEM ACTORS     #
    ###############################
    # Initialize the AE (Accreditation Entity)
    print("\n\n\n##########################################################")
    print("\n#  Inizializzazione dell\'Accreditation Entity (AE)      #")
    print("\n##########################################################")
    ae = AE('Ente di Accreditamento', accreditation_registry, did_manager)
    
    
    # set the AE did in the credential_status_registry to allow it to issue credentials
    accreditation_registry.set_accrediting_authority(ae.get_did())

    # init Issuer
    print("\n##########################################################")
    print("\n#  Inizializzazione dell\'Issuer (Università di Rennes)  #")
    print("\n##########################################################")
    # Logica che accredita l'issuer
    issuer = Issuer("Università di Rennes", dlt, ae, credential_status_registry, did_manager)
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
    verifier = Verifier("Università di Salerno", ae, did_manager=did_manager)
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