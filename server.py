import base64
import hashlib
import json
import rsa
import socket
import time
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime
from random import randint


class EncryptedLogger:

    def __init__(self, key, filepath):
        self.fernet = Fernet(key)
        self.filepath = filepath

    def log(self, message):
        message = message + ' , ' + str(datetime.now())
        encrypted_message = self.fernet.encrypt(message.encode())
        with open(self.filepath, "ab") as file:
            file.write(encrypted_message + b'\n')


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


passphrase = b'phrase'
salt = b'password'

key = generate_key(passphrase, salt)
filepath = "secure_log.log"
logger = EncryptedLogger(key, filepath)


class ATM_Server:

    def __init__(self, port=1234):
        self.og_shared_key = b'previousharedkey'
        self.clients = {}
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((socket.gethostname(), port))
        self.server.listen(3)
        self.load_keys()
        print(f"[LISTENING] on {socket.gethostname()}:{port}")

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

    def derive_keys(self, seed: bytes, conn: socket) -> tuple[bytes, Fernet]:
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
        self.clients[conn]['secret_key'] = seed.decode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=seed,
            iterations=100,
            backend=default_backend()
        )

        fernet_seed = base64.urlsafe_b64encode(
            kdf.derive(seed))
        self.clients[conn]['written_key'] = Fernet(fernet_seed)

        print(f'[DJ KHALED] I GOT THE KEYS')

    def generate_hmac(self, message: str, conn) -> str:

        new_message = message + self.clients[conn]['secret_key']
        print(f'[HMAC PRE HASH] {new_message}')
        hash_obj = hashlib.sha256(new_message.encode())
        hex_dig = hash_obj.hexdigest()
        print(f'[HMAC POST HASH] {hex_dig}')

        return hex_dig

    def verify_hmac(self, hmac_received: str, message: str, conn) -> bool:

        print(f'[HMAC RECEIVED] {hmac_received}')
        new_message = message + self.clients[conn]['secret_key']
        print(f'[HMAC PRE HASH] {new_message}')
        hash_obj = hashlib.sha256(new_message.encode())
        hex_dig = hash_obj.hexdigest()
        print(f'[HMAC CREATED] {hex_dig}')

        return hmac_received == hex_dig

    def encrypt_message(self, message_data: dict, conn) -> bytes:
        """
        Function that is used to encrypt a given message, 

        Params: 
            - message_data
                - Data to be encrypted
        
        Returns: 
            - msg_bytes: 
                - Encrypt the string using Fernet symmetric encryption
        """
        msg_bytes = message_data.encode()

        return self.clients[conn]['written_key'].encrypt(msg_bytes)

    def send_message(self, message: str, conn: socket, first=False):
        print('[SENDING MESSAGE]................................')

        if first:
            nonce = self.generate_nonce(conn)
            message_data = " | ".join([message, nonce])
        else:
            prev_nonce = self.clients[conn]['received_nonces'][-1]
            nonce = self.generate_nonce(conn)
            message_data = " | ".join([message, prev_nonce, nonce])

        print(f'[SENDING PRE-CIPHER] {message_data}')

        cipher = self.encrypt_message(message_data=message_data, conn=conn)
        print(f'[SENDING POST-CIPHER] {cipher}')
        hmac = self.generate_hmac(message=cipher.decode(), conn=conn).encode()

        conn.send(cipher)
        time.sleep(1.5)
        conn.send(hmac)

    def receive_message(self, conn):

        msg_bytes = conn.recv(4096)

        if (msg_bytes):
            print('[INCOMING MESSAGE]..........................................')
            hmac_received = conn.recv(4096).decode()
            message_bytes = self.clients[conn]['written_key'].decrypt(
                msg_bytes)
            message_data = message_bytes.decode()
            print(f'[RECEIVED MESSAGE: receive_message] {message_data}')

            if (self.verify_hmac(hmac_received=hmac_received, message=msg_bytes.decode(), conn=conn)):
                print(f'[VERIFIED] Message received has valid MAC')
            else:
                print(f'[NOT VERIFIED] Message received does not have valid MAC')
            if (message_data.split(" | ")[-1] not in self.clients[conn]['received_nonces']):
                self.clients[conn]['received_nonces'].append(
                    message_data.split()[-1])
                print(f'[NONCE] Fresh')
            # else:
                # return

            action = message_data[0]
            nonce = message_data.split(" | ")[-1]
            match action:
                case "l":
                    print("[LOGIN ATTEMPT]..............................")
                    act, user, pword, *nonces = message_data.split(" | ")
                    success = ""
                    if self.handle_login(username=user, password=pword, conn=conn):
                        success = "Successful"
                    else:
                        success = "unsuccessful"

                    tmp = " | ".join(["[LOGIN]", success])
                    self.send_message(tmp, conn)
                case "r":
                    print("[REGISTRATION ATTEMPT]..............................")
                    act, user, pword, *nonces = message_data.split(" | ")

                    self.handle_register(
                        username=user, password=pword, conn=conn)
                case "d":
                    print("[DEPOSIT ATTEMPT]..............................")
                    print(message_data)
                    act, dollars, *nonce = message_data.split(" | ")
                    dollars = float(dollars)
                    self.handle_deposit(dollars, conn)

                case "w":
                    print("[WITHDRAWAL ATTEMPT]..............................")
                    act, dollars, *nonce = message_data.split(" | ")
                    print(message_data)
                    dollars = float(dollars)
                    self.handle_withdrawal(dollars, conn)

                case "b":
                    print("[BALANCE CHECK]..............................")
                    self.handle_check_balance(conn)

            message, *nonces = message_data.split(" | ")
            time.sleep(1.5)

            return message, nonces

        else:
            time.sleep(0.05)

    def handle_login(self, username: str, password: str, conn: socket):

        tmp = f'{username} attempted login '
        logger.log(tmp)

        with open('users.json', 'r') as f:
            data = json.load(f)

            if username in data and data[username]['password'] == password:
                tmp = f'{username} login successful'
                logger.log(tmp)
                self.clients[conn]['username'] = username
                self.clients[conn]['is_login'] = True

                return True

        tmp = f'{username} login failed'
        logger.log(tmp)
        return False

    def handle_register(self, username: str, password: str, conn: socket):

        with open('users.json', 'r') as f:
            data = json.load(f)

            if username not in data.keys():

                data[username] = {
                    'password': password,
                    'balance': 0
                }
                with open('users.json', 'w') as j:
                    logger.log(f'{username} registration successful')
                    json.dump(data, j)
                    self.clients[conn]['username'] = username
                    self.clients[conn]['is_login'] = True
                    self.send_message(
                        f'[REGISTRATION] | Successful', conn)
            else:
                logger.log(f'{username} registration unsuccesful')
                self.send_message(
                    f'[REGISTRATION] | Unsuccessful', conn)

    def handle_deposit(self, deposit: float, conn: socket):

        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)
                username = self.clients[conn]['username']
                data[username]['balance'] += deposit

                with open('users.json', 'w') as j:
                    json.dump(data, j)

                logger.log(f'{username} deposit: {deposit} successful')
                self.send_message(f"[DEPOSIT] | Successful", conn)
        else:
            logger.log(f'{username} deposit failure')
            self.send_message(f"[DEPOSIT] | Unsuccessful", conn)

    def handle_withdrawal(self, withdrawal: float, conn: socket):

        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)

                username = self.clients[conn]['username']

                if (data[username]['balance'] - withdrawal >= 0):
                    self.send_message(
                        f"[WITHDRAWAL] | Successful", conn)
                    logger.log(f'{username} withdrawal: {
                               withdrawal} successful')
                else:
                    logger.log(f'{username} withdrawal failure')
                    self.send_message(
                        f"[WITHDRAWAL] | Unsuccessful: Insufficient funds, brokie", conn)
        else:
            self.send_message("[DEPOSIT] Unsuccessful", conn)

    def handle_check_balance(self, conn: socket):

        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)

                username = self.clients[conn]['username']

                balance = data[username]['balance']
                self.send_message(f"[BALANCE] {balance}", conn)

        else:
            self.send_message(f"[BALANCE] | Unsuccessful")

        logger.log(f'{username} check balance')


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

        self.derive_keys(message, conn)
        self.send_message("Done", conn, first=True)

    def generate_nonce(self, conn):

        pin = "".join(str(randint(0, 9)) for _ in range(6))
        self.clients[conn]['nonces'].append(pin)
        return pin

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
        try:
            self.clients[conn] = {
                'nonces': [],
                'received_nonces': []
            }

            data = conn.recv(1024)

            if data:
                self.handle_first_message(data, conn)

            while True:
                self.receive_message(conn)

        except ConnectionResetError:
            print(f'Client: {addr} has closed connection')
            conn.close()

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
                thread.join()
                break
        self.running = False
        self.server.close()
        thread.join()


server = ATM_Server()
server.start_server()
