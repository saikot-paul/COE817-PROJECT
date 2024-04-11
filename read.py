from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from utils import generate_key


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


passphrase = b'password'
salt = b'salt'
log_key = generate_key(passphrase=passphrase, salt=salt)
logger = EncryptedLogReader(log_key, 'audit.log')
logger.read_logs()
