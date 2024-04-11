import socket
import time
from cryptography.fernet import Fernet
from utils import generate_key, generate_hmac, verify_hmac
from random import randint

# MARK: CLASS DELCARATION


class ATM_Client:

    # MARK: CLASS INIT
    def __init__(self, host, port=1234):

        self.conn = socket.create_connection((host, port))
        self.sent_nonces = []
        self.received_nonces = []
        print('[CONNECTION] CLIENT IS CONNECTED')
        print('[CONNECTION] CLIENT IS LISTENING TO SERVER')

    # MARK: RUN ATM
    def run_atm(self):

        self.handle_first_message()

        registered = False
        while True:

            ip = input("Do you have an account (Y/N)?: ")

            if (ip.lower() == 'n'):
                print('Please create an account')
                user_name = input("Enter a username: ")
                password = input("Enter a password: ")
                data = " | ".join(['r', user_name, password])
            else:
                user_name = input("Enter a username: ")
                password = input("Enter a password: ")
                data = " | ".join(['l', user_name, password])

            self.send_message(data)
            message_arr = self.receive_message()

            if message_arr[1] == "Successful":
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
                    value = "e"
                    print("Thank you for your service!")

                case _:
                    print("Invalid action.")
                    continue

            print(value == None)
            if value is not None:
                data = " | ".join([str(action), str(value)])
                self.send_message(data)

                if action == "e":
                    break

                time.sleep(1)
                self.receive_message()
                time.sleep(1)

    # MARK: SEND MESSAGE

    def send_message(self, message: str):

        print('[SENDING MESSAGE]......................................')

        prev_nonce = self.received_nonces[-1]
        new_nonce = self.generate_nonce()
        string = " | ".join([message, prev_nonce, new_nonce])
        cipher_text = self.written_key.encrypt(string.encode())

        print(f'[SENT MESSAGE] {string}')

        hmac = generate_hmac(string, self.secret_key)

        self.conn.send(cipher_text)
        time.sleep(1.5)
        self.conn.send(hmac)

    # MARK: RECEIVE MESSAGE
    def receive_message(self):

        print('[INCOMING MESSAGE].........................................')
        cipher_text = self.conn.recv(4096)

        while not cipher_text:
            cipher_text = self.conn.recv(4096)
            time.sleep(0.5)

        hmac_received = self.conn.recv(4096)

        message_bytes = self.written_key.decrypt(cipher_text)
        message_str = message_bytes.decode()
        print(f'[RECEIVED MESSAGE] {message_str}')
        message_arr = message_str.split(" | ")

        if verify_hmac(hmac_received, message_bytes, self.secret_key):
            print('[HMAC VERIFICATION] Message is VALID')
        else:
            print('[HMAC VERIFICATION] Message is NOT VALID')
            return True

        if (message_arr[-1] not in self.received_nonces):
            self.received_nonces.append(message_arr[-1])
            print(f'[NONCE] Fresh')

        return message_arr

    # MARK: HANDLE FIRST MESSAGE

    def handle_first_message(self):

        print('[FUNCTION CALL] HANDLE FIRST MESSAGE')
        shared_key = 'sharedkey'.encode()
        prev_key = generate_key(passphrase=shared_key, salt=shared_key)
        shared_key = Fernet(prev_key)

        seed = self.generate_nonce(first=True).encode()
        cipher_text = shared_key.encrypt(seed)
        hmac_msg = generate_hmac(seed, prev_key)
        print(f'[CIPHER TEXT] GENERATED: {cipher_text}')

        self.conn.send(cipher_text)
        time.sleep(1.5)
        self.conn.send(hmac_msg)

        rev_seed = seed[::-1]
        secret_key = generate_key(passphrase=seed, salt=seed)
        written_key = generate_key(passphrase=rev_seed, salt=rev_seed)
        self.secret_key = secret_key
        self.written_key = Fernet(written_key)
        self.receive_message()
        self.send_message("ACK")

    # MARK: GENERATE NONCE

    def generate_nonce(self, first=False) -> str:
        """
        Function to generate nonces, for ensuring the freshness of each message 
        """
        pin = "".join(str(randint(0, 9)) for _ in range(6))

        if not first:
            self.sent_nonces.append(pin)
        return pin

    # MARK: CLOSE CONNECTION
    def close_connection(self):
        """
        Function that closes the connection with the server
        """
        print('[FUNCTION CALL] CLOSE CONNECTION')
        self.conn.close()
        print("[CONNECTION] closed.")


client = ATM_Client(host=socket.gethostname())
client.run_atm()
client.close_connection()
