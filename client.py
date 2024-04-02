import base64
import json
import rsa
import socket
import time
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Hash import HMAC, SHA256
from cryptography.fernet import Fernet
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2


class ATM_Client:
    def __init__(self, host, port):
        self.connection = socket.create_connection((host, port))
        print(f"Connected to server at {host}:{port}")
        self.load_keys()
        self.first_message("unique_salt_for_session")

    def first_message(self, seed: str):
        """
        Function used to establish the key distribution and derivation: 
            1. Send the seed to the server 
            2. Send the signature along with seed 
            3. Start deriving the keys when you receive an acknowledgment 
        
        Params: 
            - seed 
                - string for deriving keys 
        """
        seed_bytes = seed.encode()

        cipher_text = rsa.encrypt(seed_bytes, self.server_pub_key)
        self.connection.send(cipher_text)
        signature = rsa.sign(seed_bytes, self.priv_alice, hash_method='SHA-1')
        time.sleep(1.5)
        self.connection.send(signature)
        self.derive_keys(seed)

    def load_keys(self):
        pub_alice = "./ancillary/alice/public_alice.pem"
        priv_alice = "./ancillary/alice/private_alice.pem"
        pub_server = "./ancillary/server/public_server.pem"

        with open(pub_alice, "rb") as f:
            self.alice_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(priv_alice, "rb") as f:
            self.priv_alice = rsa.PrivateKey.load_pkcs1(f.read())
        with open(pub_server, "rb") as f:
            self.server_pub_key = rsa.PublicKey.load_pkcs1(f.read())



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

    def send_message(self, message: str):
        encrypted_message = self.written_key.encrypt(message.encode('utf-8'))
        hmac = HMAC.new(self.secret_key, encrypted_message,
                        digestmod=SHA256).hexdigest()
        message_data = {'cipher_text': encrypted_message.decode(
            'utf-8'), 'hmac': hmac}
        print(message_data)
        self.connection.send(json.dumps(message_data).encode('utf-8'))

    def close_connection(self):
        self.connection.close()
        print("Connection closed.")


if __name__ == "__main__":
    client = ATM_Client(socket.gethostname(), 1234)
    salt_str = "unique_salt_for_session"
    client.derive_keys(salt_str)
    client.send_message("Hello, Server!")
    client.close_connection()
