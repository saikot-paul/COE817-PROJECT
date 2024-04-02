import base64
import json
import rsa
import socket
import time
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Hash import HMAC, SHA256
from cryptography.fernet import Fernet
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2


class ATM_Server:

    def __init__(self, port=1234):
        self.og_shared_key = b'previousharedkey'
        self.clients = {}
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((socket.gethostname(), port))
        self.server.listen(3)
        print(f"[LISTENING] is listening on {socket.gethostname()}:{port}")

    def derive_keys(self, seed: str) -> tuple[bytes, Fernet]:
        """
        This is a function that uses key derivation function to create a keys: 
        
        Params: 
            - seed 
                - Used for the derivation from a shared key 
        Returns: 
            - secret_key 
                - This is used to hash the message and generate an hmac 
            - write_key
                - This is used to encrypt the messages
        """
        self.secret_key = PBKDF2(password="shared_secret", salt=seed, dkLen=32, count=1000,
                                 hmac_hash_module=SHA256)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=seed.encode('utf-8'),
            iterations=10000,
            backend=default_backend()
        )

        fernet_seed = base64.urlsafe_b64encode(
            kdf.derive(seed.encode('utf-8')))
        self.written_key = Fernet(fernet_seed)

        print(f'Secret key: {self.secret_key}')
        print(f'Written key: {self.written_key}')

    def encrypt_message(message: str, secret_key: bytes, written_key: Fernet) -> tuple[bytes, bytes]:
        """
        Functions that encrypts a message using Fernet encryption

        Params: 
            - message 
                - string or any data you want to encode

        Returns: 
            - cipher_text
                - Resultant bytes of message that is to be encrypted 
            - hmac 
                - HMAC of the message that is to be encrypted  
        """
        string = message.encode()
        h = HMAC.new(secret_key)
        h.update(string)
        hmac = h.digest()

        cipher_text = written_key.encrypt(string)

        print(f'Original String: {message}')
        print(f'Original Bytes: {string}')
        print(f'Ciphered String: {cipher_text}')
        print(f'HMAC: {hmac}')

        return cipher_text, hmac

    def decrypt_message(cipher_text: bytes, hmac: bytes, secret_key: bytes, written_key: Fernet):
        """
        Decrypt message and verify the hmac 

        Params: 
            - cipher_text 
                - Bytes of the encryoted message 
            - hmac 
                - HMAC that verifies the sender of the message 
            - secret_key 
                - Key that will be used to verify the hmac 
            - written_key 
                - Key that will be used to decrypt the cipher text 
        """

        unciphered_bytes = written_key.decrypt(cipher_text)
        print(f'Unciphered Bytes: {unciphered_bytes}')
        print(f'Unciphered Text: {unciphered_bytes.decode()}')

        h = HMAC.new(secret_key)
        h.update(unciphered_bytes)
        try:
            h.verify(hmac)
            return True
        except:
            print('Error')
            return False

    def handle_client(self, conn, addr):
        """
        Function used to handle a client, each client is handled in its own thread 

        Params: 
            - conn 
                - Socket that connects the server and the client 
            - addr 
                - Address of the client 
        """

        print(f'[NEW CONNECTION] from {addr}')

        self.clients[conn] = {}

        data = conn.recv(1024)
        salt = data.decode('utf-8')
        print(f'[RECEIVED] salt: {salt}')
        self.derive_keys(salt)

        while True:
            data = conn.recv(4096)
            if data:
                data_json = json.loads(data.decode('utf-8'))
                print(data_json)
            else:
                print("[WAITING] to recieve")
                time.sleep(0.5)

    def start_server(self):
        """
        Function to start a server, creates a new thread for every new connection 
        """
        self.running = True
        while self.running:
            try:
                conn, addr = self.server.accept()
                thread = threading.Thread(
                    target=self.handle_client, args=((conn, addr)))
                thread.start()
            except:
                self.running = False
                break
        self.running = False
        self.server.close()
        thread.join()


server = ATM_Server()
server.start_server()
