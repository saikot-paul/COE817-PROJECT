import base64
import json
import threading
import rsa
import socket
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
        self.connection.sendall(json.dumps(message_data).encode('utf-8'))

    def close_connection(self):
        self.connection.close()
        print("Connection closed.")


if __name__ == "__main__":
    client = ATM_Client(socket.gethostname(), 1234)
    salt = b"unique_salt_for_session"
    salt_str = "unique_salt_for_session"
    client.connection.sendall(salt)
    client.derive_keys(salt_str)
    client.send_message("Hello, Server!")
    client.close_connection()
