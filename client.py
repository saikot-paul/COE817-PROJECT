import base64
import hashlib
import rsa
import socket
import time
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from random import randint


class ATM_Client:
    def __init__(self, host, port):
        self.connection = socket.create_connection((host, port))
        self.sent_nonce = []
        print(f"[CONNECTED] to server at {host}:{port}")

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
        self.secret_key = seed

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=seed.encode('utf-8'),
            iterations=100,
            backend=default_backend()
        )

        fernet_seed = base64.urlsafe_b64encode(
            kdf.derive(seed.encode('utf-8')))
        self.written_key = Fernet(fernet_seed)

        print('[DJ KHALED] I GOT THE KEYS')

    def generate_hmac(self, message: str) -> str:

        new_message = message + self.secret_key
        print(f'[HMAC CREATION] {new_message}')
        hash_obj = hashlib.sha256(new_message.encode())
        hex_dig = hash_obj.hexdigest()
        print(f'[GENERATED HMAC] {hex_dig}')

        return hex_dig

    def verify_hmac(self, hmac_received: str, message: str) -> bool:

        print(f'[HMAC RECEIVED] {hmac_received}')
        new_message = message + self.secret_key
        print(f'[HMAC PRE HASH] {new_message}')
        hash_obj = hashlib.sha256(new_message.encode())
        hex_dig = hash_obj.hexdigest()
        print(f'[HMAC CREATED] {hex_dig}')

        return hmac_received == hex_dig

    def generate_nonce(self) -> str:
        pin = "".join(str(randint(0, 9)) for _ in range(6))
        self.sent_nonce.append(pin)
        return pin

    def encrypt_message(self, message: str) -> bytes:
        msg_bytes = message.encode()
        return self.written_key.encrypt(msg_bytes)

    def send_message(self, message: str):
        print('[SENDING MESSAGE]................................')
        nonce = self.generate_nonce()
        message_data = " | ".join([message, nonce])
        print(f'[SENDING PRE-CIPHER] {message_data}')

        cipher = self.encrypt_message(message=message_data)
        print(f'[SENDING POST-CIPHER] {cipher}')
        hmac = self.generate_hmac(cipher.decode()).encode()

        self.connection.send(cipher)
        time.sleep(1.5)
        self.connection.send(hmac)

    def receive_message(self):

        print(f'[INCOMING MESSAGE]............................')
        msg_bytes = self.connection.recv(4096)
        hmac_received = self.connection.recv(4096).decode()
        message = self.written_key.decrypt(msg_bytes).decode()

        action, *nonces = message.split(" | ")

        print(f"[RECEIVED MESSAGE] {message}")

        if (self.verify_hmac(hmac_received, msg_bytes.decode())):
            print(f'[VERIFIED] Message received has valid HMAC')
        else:
            print(f'[NOT VERIFIED] Message received does not have valid MAC')

        return action, message

    def run_atm(self):

        self.load_keys()
        self.first_message(self.generate_nonce())
        first, message = self.receive_message()
        if (first == "Done"):

            while True:
                register = input("Are you registered (Y/N): ")

                if (register.lower() == 'n'):
                    print('Please create an account')
                    user_name = input("Enter a username: ")
                    password = input("Enter a password: ")
                    data = " | ".join(['r', user_name, password])
                else:
                    user_name = input("Enter a username: ")
                    password = input("Enter a password: ")
                    data = " | ".join(['l', user_name, password])

                self.send_message(data)
                first, message = self.receive_message()
                print(message)

                if (message.split(" | ")[1] == "Successful"):
                    break

            while True:
                print(
                    "Please enter an action: d - deposit, w - withdrawal, b - balance, e - exit")
                action = input("Action: ")

                action = action.lower()
                value = None  # Initialize value

                match action:
                    case "d":
                        value = float(
                            input("Enter the value you wish to deposit: "))
                        if value <= 0:
                            print("Cannot deposit amount specified")
                            continue

                    case "w":
                        value = float(
                            input("Enter the value you wish to withdraw: "))
                        if value <= 0:
                            print("Cannot withdraw amount specified")
                            continue

                    case "b":
                        value = "balance"

                    case "e":
                        print("Thank you for your service!")
                        break

                    case _:
                        print("Invalid action.")
                        continue

                print(value == None)
                if value is not None:
                    data = " | ".join([str(action), str(value)])
                    self.send_message(data)
                    time.sleep(1)
                    self.receive_message()
                    time.sleep(1)



    def close_connection(self):
        self.connection.close()
        print("[CONNECTION] closed.")


if __name__ == "__main__":
    client = ATM_Client(socket.gethostname(), 1234)
    client.run_atm()
    client.close_connection()
