import base64
import hashlib
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime


def generate_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10,
        backend=default_backend()
    )
    fernet_seed = base64.urlsafe_b64encode(
        kdf.derive(passphrase))

    return fernet_seed


def generate_hmac(message, key, hash_func=hashlib.sha256):

    if (isinstance(message, str)):
        message = message.encode()

    if (isinstance(key, str)):
        key = key.encode()

    return hmac.new(key, message, hash_func).digest()


def verify_hmac(hmac_received, message, key, hash_func=hashlib.sha256):

    computed_hmac = generate_hmac(message, key, hash_func)

    return hmac.compare_digest(computed_hmac, hmac_received)


class EncryptedLogger:

    def __init__(self, key, filepath):
        self.fernet = Fernet(key)
        self.filepath = filepath

    def log(self, message):
        message = message + ' , ' + str(datetime.now())
        encrypted_message = self.fernet.encrypt(message.encode())
        with open(self.filepath, "ab") as file:
            file.write(encrypted_message + b'\n')
