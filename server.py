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
        self.load_keys()
        print(f"[LISTENING] is listening on {socket.gethostname()}:{port}")

    def load_keys(self):
        pub_alice = "./ancillary/alice/public_alice.pem"
        pub_bob = "./ancillary/bob/public_bob.pem"
        pub_charlie = "./ancillary/charlie/public_charlie.pem"
        pub_server = "./ancillary/server/public_server.pem"
        priv_server = "./ancillary/server/private_server.pem"

        with open(pub_alice, "rb") as f:
            self.alice_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(pub_bob, "rb") as f:
            self.bob_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(pub_charlie, "rb") as f:
            self.charlie_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(pub_server, "rb") as f:
            self.server_pub_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(priv_server, "rb") as f:
            self.priv_key = rsa.PrivateKey.load_pkcs1(f.read())

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

    def handle_first_message(self, data: bytes, conn: socket):
        message = rsa.decrypt(data, self.priv_key)
        time.sleep(1.5)
        print(f'[RECEIVED MESSAGE] salt: {message.decode()}')
        data = conn.recv(1024)
        try:
            rsa.verify(message, data, self.alice_key)
            print('[VERIFCATION] message is verified')
        except:
            print('[VERICATION] message is not verified')

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

        if data:
            self.handle_first_message(data, conn)


        while True:
            data = conn.recv(4096)
            if data:
                data_json = json.loads(data.decode('utf-8'))
                print(data_json)
            else:
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
