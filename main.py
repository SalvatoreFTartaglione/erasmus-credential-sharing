from DIDManager import DIDManager
from DLT.AccreditationRegistry import AccreditationRegistry
from DLT.CredentialStatusRegistry import CredentialStatusRegistry
from DLT.DLT import DLT
from Issuer import Issuer
from Verifier import Verifier
from AE import AE
from Student import Student
import time
import random

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
        print("\n#          Verifier non accreditato                      #")
        print("\n##########################################################")
        print('\n')


    print("\n##########################################################")
    print("\n#          Creazione dello studente                      #")
    print("\n##########################################################")
    print('\n')

    studente = Student(name ="Salvatore", did_manager=did_manager, issuer=issuer)

    print("\n############################################################################")
    print(f"\n#        Studente {studente.get_nome()} creato con successo               #")
    print("\n############################################################################")
    print('\n')

    print("\n########################################################")
    print(f"\n#        Creazione delle credenziali                  #")
    print("\n########################################################")
    print('\n')
    studente.create_email_and_password()

    print("Inserire le credenziali per accedere al wallet personale")
    email = input("Email: ")
    password = input("Password: ")

    while email != studente.get_email() or password != studente.get_password():
        print("Credenziali errate. Riprovare:")
        email = input("Email: ")
        password = input("Password: ")

    otp = str(random.randint(100000, 999999))
    print(f"\nUn OTP è stato inviato all'indirizzo registrato ({studente.get_email()}).")
    print(f"OTP generato: {otp}")

    attempts = 0
    max_attempts = 5
    wait_time = 2  # secondi

    while True:
        user_otp = input("Inserisci OTP ricevuto: ")
        if user_otp == otp:
            break
        else:
            attempts += 1
            if attempts >= max_attempts:
                print("Hai superato il numero massimo di tentativi. Accesso bloccato.")
                exit(1)
            print("OTP errato. Riprova.")
            time.sleep(wait_time)
            wait_time *= 2

    print("\n#############################################################")
    print(f"\n#          Autenticazione avvenuta con successo!           #")
    print("\n#############################################################")
    print('\n')

    studente.create_wallet()

    if not studente.get_wallet():
        print("C'è stato un errore.")
        exit(1)

    studente.send_public_key_to_issuer()
    menu_principale(studente)


    # Return the initialized actors
    return {
        "dlt": dlt,
        "accreditation_registry": accreditation_registry,
        #"credential_status_registry": credential_status_registry,
        "ae": ae,
        "issuer": issuer,
        "verifier": verifier,
        "student": studente,
    }


def checkInput(lista_utente, lista_esami):
    # Rimuove eventuali spazi e verifica il formato corretto (solo numeri separati da ;)
    cleaned_input = lista_utente.replace(" ", "")

    # Controllo formato: accetta solo cifre e `;`
    if not all(c.isdigit() or c == ';' for c in cleaned_input):
        return False, []

    # Evita input vuoti o con solo separatori
    if not cleaned_input or cleaned_input.startswith(';') or cleaned_input.endswith(';') or ';;' in cleaned_input:
        return False, []

    try:
        user_ids = list(map(int, cleaned_input.split(';')))
    except ValueError:
        return False, []

    # Controllo che tutti gli ID siano nella lista degli esami
    id_non_presenti = [i for i in user_ids if i not in lista_esami]

    if id_non_presenti:
        return False, id_non_presenti

    return True, []

def menu_principale(studente):
    while True:
        print(f"Benvenuto nel tuo wallet {studente.get_nome()}.")
        print("[1] Per ottenere la credenziale")
        print("[2] Per passare alla modalità di generazione della presentazione")
        choice = input("")

        while choice != "1" and choice != "2":
            print("Numero errato. Riprova:")
            choice = input("")

        if choice == "1":
            print("MENU CREDENZIALE")
            string = input("Immettere la password per avviare il processo di richiesta della credenziale all'università ospitante\npassword: ")
            while string != studente.get_password():
                print("Password errata. Riprova.")
                string = input("password: ")
            print("Password corretta.")
            print("Sto inviando una richiesta di credenziale all'università ospitante.\n")
        else:
            menu_presentazione(studente)

def menu_presentazione(studente):
    print("MENU PRESENTAZIONE")
    print("Digitare '-1' se si vuole tornare indietro, altrimenti immettere gli identificativi degli esami, separati da ';'")
    print("ESAMI;ID")
    # stampa degli esami con id
    lista_esami = [1, 2, 3, 4, 5]  # Id degli esami

    while True:
        user_input = input("")
        if user_input == "-1":
            return  # torna al menu principale

        verified, lista_di_id_sbagliati = checkInput(user_input, lista_esami)
        while not verified:
            if len(lista_di_id_sbagliati) != 0:
                print(f"Gli id {lista_di_id_sbagliati} non sono presenti nella lista degli esami. Riprova.")
            else:
                print("Formato sbagliato, ogni id deve essere separato da ';'. Riprova.")
            user_input = input("")
            if user_input == "-1":
                return
            verified, lista_di_id_sbagliati = checkInput(user_input, lista_esami)

        # Se verified è True
        print("Input valido. Procedo con la generazione della presentazione.")
        break


if __name__ == "__main__":

    actors = init_actors()