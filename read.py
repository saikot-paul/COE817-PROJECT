from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generate_key(passphrase: bytes, seed: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=seed,
        iterations=100,
        backend=default_backend()
    )
    fernet_seed = base64.urlsafe_b64encode(
        kdf.derive(passphrase))

    return fernet_seed


class EncryptedLogReader:
    def __init__(self, key, filepath):
        self.fernet = Fernet(key)
        self.filepath = filepath

    def read_logs(self):
        try:
            with open(self.filepath, "rb") as file:
                log_entries = file.readlines()

            for entry in log_entries:
                decrypted_message = self.fernet.decrypt(entry).decode()
                print(decrypted_message)
        except Exception as e:
            print(f"Failed to read or decrypt log: {e}")


# Setup for using the logger and reader
passphrase = b'phrase'
salt = b'password'
key = generate_key(passphrase, salt)
filepath = "secure_log.log"

reader = EncryptedLogReader(key, filepath)
reader.read_logs()
