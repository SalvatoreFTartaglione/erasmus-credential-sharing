from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

class TLS:
    def __init__(self):
        pass

    @staticmethod
    # Simulazione TLS Handshake: il client genera una chiave AES e la invia cifrata al server
    def simulate_tls_handshake(client_private_key, client_public_key, server_public_key):
        # Il client genera una chiave AES casuale
        aes_key = os.urandom(32)  # AES-256

        # Cifra la chiave AES con la chiave pubblica del server
        encrypted_key = server_public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # In un vero handshake, il server riceverebbe questa chiave e la decifrerebbe col suo private key
        return encrypted_key, aes_key  # restituisce anche l'originale (per confronto)

    @staticmethod
    def server_receive_tls_key(encrypted_key, server_private_key):
        aes_key = server_private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return aes_key

    @staticmethod
    def encrypt_message_aes(aes_key, plaintext):
        iv = os.urandom(16)  # Initialization Vector per AES CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Padding a blocchi di 16 byte
        padding_len = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_len] * padding_len)

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv, ciphertext

    @staticmethod
    def decrypt_message_aes(aes_key, iv, ciphertext):
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        padding_len = padded_plaintext[-1]
        return padded_plaintext[:-padding_len]

    @staticmethod
    def load_public_key_from_pem(pem_str):
        return serialization.load_pem_public_key(
            pem_str.encode(),
            backend=default_backend()
        )

    @staticmethod
    def load_private_key_from_pem(pem_str):
        return serialization.load_pem_private_key(
            pem_str.encode(),
            password=None,
            backend=default_backend()
        )
