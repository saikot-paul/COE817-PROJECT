import json
import socket
import time
import threading
import traceback
from cryptography.fernet import Fernet
from random import randint
from utils import EncryptedLogger, generate_key, generate_hmac, verify_hmac


# MARK: INITIAL CONFIG
passphrase = b'password'
salt = b'salt'
log_key = generate_key(passphrase=passphrase, salt=salt)
logger = EncryptedLogger(log_key, 'audit.log')


# MARK: CLASS DECLARATION
class ATM_Server:

    # MARK: CLASS INIT
    def __init__(self, port=1234):
        self.clients = {}
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((socket.gethostname(), port))
        self.server.listen(3)
        print(f"[LISTENING] on {socket.gethostname()}:{port}")

    # MARK: START SERVER
    def start_server(self) -> None:
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

    # MARK: HANDLE CLIENT
    def handle_client(self, conn: socket.socket, addr: any) -> None:
        """
        Function used to handle a client

        Params: 
            - conn: socket 
                - socket that connects server to client 
            - addr
                - address of the client

        Returns: 
            - None
        """
        print('[FUNCTION CALL] HANDLE CLIENT')
        print(f'[NEW CONNECTION] from {addr}')

        self.clients[conn] = {
            'sent_nonces': [],
            'received_nonces': []
        }

        self.handle_first_message(conn)

        try:
            while True:

                cipher_text = conn.recv(4096)

                if cipher_text:
                    exit = self.handle_receive_message(cipher_text, conn)
                else:
                    time.sleep(1.5)

                if exit:
                    break

        except Exception as e:
            print(f'[ERROR] Client: {
                addr} has closed connection or an error occurred: {e}')
            traceback.print_exc()
        finally:
            conn.close()
            del self.clients[conn]  # Clean up client list
            print(f'[CONNECTION CLOSED] with {addr}')

    # MARK: HANDLE RECEIVE MESSAGE
    def handle_receive_message(self, cipher_text: bytes, conn: socket.socket) -> bool:
        """
        Function used to handle messages. The function gets called in the handle client function, after receiving the cipher text. 
        In here we check the socket for the hmac received. We decipher the text received and verify the HMAC and then call the 
        handle_atm_func method in order to serve the customer. 

        Params: 
            - cipher_text: str

        """
        print('[INCOMING MESSAGE]..........................................')
        hmac_received = conn.recv(4096)
        message_bytes = self.clients[conn]['written_key'].decrypt(cipher_text)
        message_str = message_bytes.decode()
        print(f'[RECEIVED MESSAGE] {message_str}')

        message_arr = message_str.split(" | ")

        secret_key = self.clients[conn]['secret_key']
        if verify_hmac(hmac_received, message_bytes, secret_key):
            print('[HMAC VERIFICATION] Message is VALID')
        else:
            print('[HMAC VERIFICATION] Message is NOT VALID')
            return True

        if (message_arr[-1] not in self.clients[conn]['received_nonces']):
            self.clients[conn]['received_nonces'].append(message_arr[-1])
            print(f'[NONCE] Fresh')

        exit = self.handle_atm_functions(message_arr, conn)

        return exit

    # MARK: HANDLE SEND MESSAGE
    def handle_send_message(self, message: str, conn: socket.socket, first=False) -> None:

        if first:
            new_nonce = self.generate_nonce(conn)
            string = " | ".join([message, new_nonce])
        else:
            prev_nonce = self.clients[conn]['received_nonces'][-1]
            new_nonce = self.generate_nonce(conn)
            string = " | ".join([message, prev_nonce, new_nonce])

        cipher_text = self.clients[conn]['written_key'].encrypt(
            string.encode())
        secret_key = self.clients[conn]['secret_key']

        hmac = generate_hmac(message=string, key=secret_key)

        conn.send(cipher_text)
        time.sleep(1.5)
        conn.send(hmac)

    # MARK: GENERATE NONCE

    def generate_nonce(self, conn):

        pin = "".join(str(randint(0, 9)) for _ in range(6))
        self.clients[conn]['sent_nonces'].append(pin)
        return pin

    # MARK: HANDLE ATM FUNCTIONS
    def handle_atm_functions(self, message_arr: list[str], conn: socket.socket):
        """
        Dispatching function that calls on other functions to handle ATM requests
        """

        action = message_arr[0]

        match action:
            case "l":
                print("[LOGIN ATTEMPT]..............................")
                act, user, pword, *nonces = message_arr
                self.handle_login(user, pword, conn)
            case "r":
                print("[REGISTRATION ATTEMPT]..............................")
                act, user, pword, *nonces = message_arr

                self.handle_register(
                    username=user, password=pword, conn=conn)
            case "d":
                print("[DEPOSIT ATTEMPT]..............................")
                act, dollars, *nonce = message_arr
                dollars = float(dollars)
                self.handle_deposit(dollars, conn)

            case "w":
                print("[WITHDRAWAL ATTEMPT]..............................")
                act, dollars, *nonce = message_arr
                dollars = float(dollars)
                self.handle_withdrawal(dollars, conn)

            case "b":
                print("[BALANCE CHECK]..............................")
                self.handle_check_balance(conn)

            case "e":
                return True

        return False

    # MARK: HANDLE LOGIN
    def handle_login(self, username: str, password: str, conn: socket):

        tmp = f'{username} attempted login '
        logger.log(tmp)

        with open('users.json', 'r') as f:
            data = json.load(f)

            if username in data and data[username]['password'] == password:
                self.clients[conn]['username'] = username
                self.clients[conn]['is_login'] = True
                s = "Successful"
            else:
                s = "Unsuccessful"

        tmp = f'{username} Login {s}'
        logger.log(tmp)
        self.handle_send_message(" | ".join(["[LOGIN]", s]), conn)

    # MARK: HANDLE REGISTER
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
                    self.handle_send_message(
                        f'[REGISTRATION] | Successful', conn)
            else:
                logger.log(f'{username} registration unsuccesful')
                self.handle_send_message(
                    f'[REGISTRATION] | Unsuccessful', conn)

    # MARK: HANDLE DEPOSIT
    def handle_deposit(self, deposit: float, conn: socket):

        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)
                username = self.clients[conn]['username']
                data[username]['balance'] += deposit

                with open('users.json', 'w') as j:
                    json.dump(data, j)

                logger.log(f'{username} deposit: {deposit} successful')
                self.handle_send_message(f"[DEPOSIT] | Successful", conn)
        else:
            logger.log(f'{username} deposit failure')
            self.handle_send_message(f"[DEPOSIT] | Unsuccessful", conn)

    # MARK: HANDLE WITHDRAWAL
    def handle_withdrawal(self, withdrawal: float, conn: socket):

        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)

                username = self.clients[conn]['username']

                if (data[username]['balance'] - withdrawal >= 0):
                    data[username]['balance'] -= withdrawal

                    with open('users.json', 'w') as j:
                        json.dump(data, j)

                    self.handle_send_message(
                        f"[WITHDRAWAL] | Successful", conn)
                    logger.log(f'{username} withdrawal: {
                               withdrawal} successful')
                else:
                    logger.log(f'{username} withdrawal failure')
                    self.handle_send_message(
                        f"[WITHDRAWAL] | Unsuccessful: Insufficient funds, brokie", conn)
        else:
            self.handle_send_message("[DEPOSIT] Unsuccessful", conn)

    # MARK: HANDLE BALANCE
    def handle_check_balance(self, conn: socket):

        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)

                username = self.clients[conn]['username']

                balance = data[username]['balance']
                self.handle_send_message(f"[BALANCE] {balance}", conn)

        else:
            self.handle_send_message(f"[BALANCE] | Unsuccessful")

        logger.log(f'{username} check balance')

    # MARK: HANDLE FIRST MESSAGE
    def handle_first_message(self, conn: socket):
        """
        Function is used to handle the first message with a client to generate/derive new keys 

        Params: 
            - conn: socket 
                - this is the socket that serves a client 

        Returns: 
            - None 
        """

        print('[FUNCTION CALL] HANDLE FIRST MESSAGE')
        shared_key = 'sharedkey'.encode()
        prev_key = generate_key(passphrase=shared_key, salt=shared_key)
        shared_key = Fernet(prev_key)

        cipher_text = conn.recv(4096)
        time.sleep(1.5)
        hmac_received = conn.recv(4096)
        seed = shared_key.decrypt(cipher_text)

        print(f'[VERIFYING HMAC] {verify_hmac(
            hmac_received, seed, prev_key)}')
        print(f'[MESSAGE RECEIVED] {seed.decode()}')

        rev_seed = seed[::-1]
        secret_key = generate_key(passphrase=seed, salt=seed)
        written_key = generate_key(passphrase=rev_seed, salt=rev_seed)
        self.clients[conn]['secret_key'] = secret_key
        self.clients[conn]['written_key'] = Fernet(written_key)

        print(f'[DERIVED KEYS] KEYS HAVE BEEN CREATED')

        self.handle_send_message("DONE", conn, first=True)
        time.sleep(0.5)

        cipher_text = conn.recv(4096)
        self.handle_receive_message(cipher_text, conn)


server = ATM_Server()
server.start_server()
