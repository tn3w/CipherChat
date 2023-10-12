import os
import re
import sys
import stem
import shutil
import random
import secrets
import platform
import requests
from time import time
from stem import control
from getpass import getpass
from sys import argv as ARGUMENTS
from stem.process import launch_tor_with_config
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Optional, Tuple

VERSION = 1.0

LOGO = '''
 dP""b8 88 88""Yb 88  88 888888 88""Yb  dP""b8 88  88    db    888888 
dP   `" 88 88__dP 88  88 88__   88__dP dP   `" 88  88   dPYb     88   
Yb      88 88"""  888888 88""   88"Yb  Yb      888888  dP__Yb    88   
 YboodP 88 88     88  88 888888 88  Yb  YboodP 88  88 dP""""Yb   88   

-~-    Programmed by TN3W - https://github.com/tn3w/CipherChat    -~-
'''
CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
NEEDED_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "needed")
DATA_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "data")

GUTMANN_PATTERNS = [bytes([i % 256] * 100000) for i in range(35)]
DOD_PATTERNS = [bytes([0x00] * 100000), bytes([0xFF] *
                                              100000), bytes([0x00] * 100000)]


def clear_console():
    "Cleans the console and shows logo"

    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)


def get_password_strength(password: str) -> int:
    """
    Function to get a password strength from 0 (bad) to 100% (good)

    :param password: The password to check
    """

    strength = (len(password) * 62.5) / 20

    if strength > 70:
        strength = 70

    if re.search(r'[A-Z]', password):
        strength += 12.5
    if re.search(r'[a-z]', password):
        strength += 12.5
    if re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', password):
        strength += 12.5

    if strength > 100:
        strength = 100

    return round(strength)


def generate_random_string(length: int, with_punctuation: bool = True, with_letters: bool = True):
    """
    Generates a random string

    :param length: The length of the string
    :param with_punctuation: Whether to include special characters
    :param with_letters: Whether letters should be included
    """

    characters = "0123456789"

    if with_punctuation:
        characters += r"!\"#$%&'()*+,-.:;<=>?@[\]^_`{|}~"

    if with_letters:
        characters += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string


def get_system_architecture() -> Tuple[str, str]:
    "Function to get the correct system information"

    system = platform.system()
    if system == "Darwin":
        system = "macOS"

    machine_mappings = {
        "AMD64": "x86_64",
        "i386": "i686"
    }

    machine = platform.machine()

    machine = machine_mappings.get(machine, "x86_64")

    return system, machine


def shorten_text(text: str, length: int) -> str:
    """
    Function to shorten the text and append "...".

    :param text: The text to be shortened
    :param length: The length of the text
    """

    if len(text) > length:
        text = text[:length] + "..."
    return text


SYSTEM, MACHINE = get_system_architecture()
SYSTEM_INFO = f"{SYSTEM} ({MACHINE})"
TOR_PATH = {"Windows": f"C:\\Users\\{os.environ.get('USERNAME')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"}.get(SYSTEM, "/usr/bin/tor")


class Tor:
    """
    Collection of functions that have something to do with the Tor network
    """

    def start_tor_daemon():
        """
        Launches The Onion Router Daemom
        """

        if not Tor.is_tor_daemon_alive():
            launch_tor_with_config(
                tor_cmd=TOR_PATH,
                config={
                    'SocksPort': '9050',
                    'ControlPort': '9051',
                    'Bridge': ' obfs4 [2001:19f0:4401:87c:5400:3ff:feb7:8cfc]:4444 55346F385B6FB7069D1588CE842DBE88F90F90C5 cert=fbtptOz8dA1Sz6Fl4i0k8KNqBVt8ueGmBHUBixB1/0QCyxwct9w4TwyXJe9kjwQCeR9SVw iat-mode=0'
                },
            )

    def is_tor_daemon_alive() -> bool:
        """
        Function to check if the Tor Daemon is currently running
        """

        try:
            with control.Controller.from_port(port=9051) as controller:
                controller.authenticate()

                if controller.is_alive():
                    return True
                else:
                    print("[Error] Tor is probably not installed.")
        except stem.SocketError as socket_error:
            print(f"[Error] Error connecting to the Tor Control Port '{socket_error}'")
        except stem.connection.AuthenticationFailure as authentication_error:
            print(f"[Error] Tor Authentication error '{authentication_error}'")
        return False

    def get_request_session() -> requests.session:
        """
        Creates gate connection and returns requests.session
        """

        def new_tor_signal():
            with control.Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(stem.Signal.NEWNYM)

        new_session = requests.session()

        try:
            new_tor_signal()
        except (stem.SocketError, stem.AuthenticationFailure, stem.SignalError):
            Tor.start_tor_daemon()
            new_tor_signal()
        except Exception as e:
            print(f"[Error] Request Error: '{e}'")

        new_session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

        return new_session


class SecureDelete:
    """
    Class for secure deletion of files or folders
    """

    @staticmethod
    def file(file_path: str) -> None:
        """
        Function to securely delete a file by replacing it first with random characters and then according to Gutmann patterns and DoD 5220.22-M patterns
        :param file_path: The path to the file
        """

        if not os.path.isfile(file_path):
            return

        file_size = os.path.getsize(file_path)
        for _ in range(5):
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)

                with open(file_path, 'wb') as file:
                    file.write(os.urandom(file_size))

                os.remove(file_path)

                with open(file_path, 'ab') as file:
                    file.seek(0, os.SEEK_END)

                    # Gutmann Pattern
                    for pattern in GUTMANN_PATTERNS:
                        file.write(pattern)

                    # DoD 5220.22-M Pattern
                    for pattern in DOD_PATTERNS:
                        file.write(pattern)
            except Exception:
                pass

        try:
            os.remove(file_path)
        except Exception:
            pass

    @staticmethod
    def directory(directory_path):
        """
        Securely deletes entire folders with files and subfolders
        :param directory_path: The path to the directory
        """

        for file_or_dir in os.listdir(directory_path):
            path = os.path.join(directory_path, file_or_dir)
            if os.path.isfile(path):
                SecureDelete.file(path)
            elif os.path.isdir(path):
                SecureDelete.directory(path)

        try:
            shutil.rmtree(directory_path)
        except Exception:
            pass


class SymmetricEncryption:
    """
    Implementation of symmetric encryption with AES
    """

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        self.password = password.encode()
        self.salt_length = salt_length

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = urlsafe_b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[
            self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()


if "-a" in ARGUMENTS or "--about" in ARGUMENTS:
    clear_console()
    print(f"Current version: {VERSION}")
    print("CipherChat is used for secure chatting with end to end encryption and anonymous use of the Tor network for sending / receiving messages, it is released under the GPL v3 on Github. Setting up and using secure chat servers is made easy.")
    print("Use `python cipherchat.py -h` if you want to know all commands. To start use `python cipherchat.py`.")
    sys.exit(0)

if "-k" in ARGUMENTS or "--killswitch" in ARGUMENTS:
    clear_console()
    print("All files will be overwritten and deleted several times... (This can take several seconds)")
    start_time = time()
    if os.path.isdir(DATA_DIR_PATH):
        SecureDelete.directory(DATA_DIR_PATH)
    end_time = time()
    clear_console()
    print("Completed, all files are irrevocably deleted.",
          "(took", end_time - start_time, "s)")
    sys.exit(0)

if "-h" in ARGUMENTS or "--help" in ARGUMENTS:
    clear_console()
    print("> To start the client, simply do not use any arguments.")
    print("-h, --help                   Displays this help menu.")
    print("-a, --about                  Displays an About Cipherchat overview")
    print("-k, --killswitch             Immediately deletes all data in the data Dir and thus all persistent user data")
    print("-t, --torhiddenservice       Launches a CipherChat Tor Hidden Service")
    print("-d, --directchat             Creates a direct chat room")
    sys.exit(0)

# Use Persistent Storage?
PERSISTENT_STORAGE_CONF_PATH = os.path.join(
    NEEDED_DIR_PATH, "persistent-storage.conf")
if not os.path.isfile(PERSISTENT_STORAGE_CONF_PATH) and not os.path.isdir(DATA_DIR_PATH):
    while True:
        clear_console()
        print("(Please note that if Persistent Storage is not enabled, any messages or files retrieved will not be stored. The server deletes them after a single request, and no data is saved on the client side due to this setting.)")
        persistent_storage = input(
            "Do you want to use encrypted persistent storage? [Y or n] ")

        if persistent_storage.lower() in ["y", "yes"]:
            USE_PERSISTENT_STORAGE = True
            break
        elif persistent_storage.lower() in ["n", "no"]:
            USE_PERSISTENT_STORAGE = False
            break
        else:
            print("[Error] Input invalid, enter either 'Y' or 'n'")
            input("Enter: ")

elif os.path.isfile(PERSISTENT_STORAGE_CONF_PATH):
    USE_PERSISTENT_STORAGE = False
elif os.path.isdir(DATA_DIR_PATH):
    USE_PERSISTENT_STORAGE = True

if not USE_PERSISTENT_STORAGE and not os.path.isfile(PERSISTENT_STORAGE_CONF_PATH):
    if not os.path.isdir(NEEDED_DIR_PATH):
        os.mkdir(NEEDED_DIR_PATH)

    open(PERSISTENT_STORAGE_CONF_PATH, "x")

KEY_FILE_PATH_CONF_PATH = os.path.join(DATA_DIR_PATH, "keyfile-path.conf")

# Set a master password if Persistent Storage is enabled
if USE_PERSISTENT_STORAGE:
    if os.path.isfile(KEY_FILE_PATH_CONF_PATH):
        with open(KEY_FILE_PATH_CONF_PATH, "r", encoding="utf-8") as readable_file:
            crypted_key_file_path = readable_file.read()

        while True:
            clear_console()
            master_password = getpass("Enter your master password: ")

            # Trying Password on Key File Path Conf File
            try:
                key_file_path = SymmetricEncryption(master_password).decrypt(crypted_key_file_path)
            except Exception as e:
                print(f"[Error] Error decrypting the key file path configuration file: '{e}'")
                print("This is probably because you entered the wrong password or the configuration file is corrupt.")
                input("Enter: ")
            else:
                KEY_FILE_PATH = key_file_path
                break
    else:
        while True:
            clear_console()
            master_password = getpass(
                "Please enter a secure master password: ")

            password_strength = get_password_strength(master_password)
            print("Security Score:", password_strength, "/ 100%\n")

            if len(master_password) < 12:
                print("[Error] Master password must consist of at least 12 characters (a good password usually has 16 characters)")
                input("Enter: ")
            elif not re.search(r'[A-Z]', master_password):
                print("[Error] Your password does not contain a capital letter.")
                input("Enter: ")
            elif not re.search(r'[a-z]', master_password):
                print("[Error] Your password does not contain a lowercase letter.")
                input("Enter: ")
            elif not re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', master_password):
                print("[Error] Your password does not contain any special characters.")
                input("Enter: ")
            else:
                KEEP = True
                if password_strength <= 85:
                    keep_input = input(
                        "Your password is insecure, enter k to keep it: ")
                    if not keep_input.lower() in ["k", "keep"]:
                        KEEP = False
                    else:
                        print("")

                if KEEP:
                    repeat_master_password = getpass(
                        "Please repeat your master password: ")
                    if not repeat_master_password == master_password:
                        print("[Error] The passwords do not match.")
                        input("Enter: ")
                    else:
                        break

        # Get Key File Path
        while True:
            clear_console()
            keyfile_path = input(
                "Enter a folder where the keyfile should be saved or Enter: ")

            if keyfile_path == "":
                KEY_FILE_PATH = os.path.join(DATA_DIR_PATH, "keys.conf")
                break

            if not os.path.isdir(keyfile_path):
                print("[Error] The given folder does not exist.")
                input("Enter: ")
            else:
                KEY_FILE_PATH = os.path.join(keyfile_path, "keys.conf")
                break

        # Create Key File Path Configuration File
        if not os.path.isdir(DATA_DIR_PATH):
            os.mkdir(DATA_DIR_PATH)

        crypted_key_file_path = SymmetricEncryption(
            master_password).encrypt(KEY_FILE_PATH)

        with open(KEY_FILE_PATH_CONF_PATH, "w", encoding="utf-8") as writeable_file:
            writeable_file.write(crypted_key_file_path)

    # Get Secret Key
    if not os.path.isfile(KEY_FILE_PATH):
        SECRET_KEY = generate_random_string(512)

        crypted_secret_key = SymmetricEncryption(
            master_password).encrypt(SECRET_KEY)

        with open(KEY_FILE_PATH, "w", encoding="utf-8") as writeable_file:
            writeable_file.write(crypted_secret_key)
    else:
        with open(KEY_FILE_PATH, "r", encoding="utf-8") as readable_file:
            crypted_secret_key = readable_file.read()

        SECRET_KEY = SymmetricEncryption(
            master_password).decrypt(crypted_secret_key)

FACTS = ["Tor is a valuable tool for activists, journalists, and individuals in countries with restricted internet access, allowing them to communicate and access information without fear of surveillance.", "The Tor Browser was first created by the U.S. Naval Research Laboratory.", "The name 'Tor' originally stood for 'The Onion Router', referring to its multiple layers of encryption, much like the layers of an onion.", "The Tor Browser is open-source software, which means its source code is freely available for anyone to inspect, modify, and contribute to.", "Tor is designed to prioritize user privacy by routing internet traffic through a network of volunteer-operated servers, making it difficult to trace the origin and destination of data.",
         "The development of Tor has received funding from various government agencies, including the U.S. government, due to its importance in promoting online privacy and security.", "Tor allows websites to operate as hidden services, which are only accessible through the Tor network. This has led to the creation of websites that can't be easily traced or taken down.", "Websites on the Tor network often have addresses ending in '.onion' instead of the usual '.com' or '.org', adding to the uniqueness of the network.", "The strength of the Tor network lies in its thousands of volunteer-run relays worldwide. Users' data is passed through multiple relays, making it extremely difficult for anyone to trace their online activities."]

clear_console()
print("Attempts to launch Tor Daemon...")

try:
    Tor.start_tor_daemon()
except Exception:
    # FIXME: LOG
    pass

# Tor Daemon Download
while True:
    clear_console()
    print("Check if the Tor daemon is running correctly...")
    if Tor.is_tor_daemon_alive():
        break

    TORRC_PATH = {"Windows": f"C:\\Users\\{os.environ.get('USERNAME')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\Tor\\torrc"}.get(SYSTEM, "/usr/local/etc/tor/")

    print("System is", SYSTEM_INFO)
    print("\n-- TOR Installation Instructions --")
    print(f"Shh... Did you know? {random.choice(FACTS)}\n")
    print("1. Tor Download")
    print("- Go to the following website with a web browser of your choice: https://www.torproject.org/download/")
    print(
        f"- Press 'Download for {SYSTEM}' and wait until it is downloaded.\n")
    print("2. Installation of the Tor Browser")
    print("- Now press on the downloaded file until an installation window opens.")
    print("- Follow the instructions!\n")
    print("3. Setup")
    print("- Do not connect to the Tor network yet!")
    print("- Open the installed Tor browser, then go to Settings > Privacy and Security and scroll down to Security and select 'Safest'.")
    print("- Now go to Settings > Connection, scroll down to the Bridges section and to 'Add a new bridge' and select 'Request a bridge from torproject.org'. You will now have to solve a captcha, once you have done that you will have fresh bridges that will hide your Tor usage from your ISP.\n")
    print("\n! After that close the Tor Browser !")
    input("Everything installed? Press Enter ")

    try:
        Tor.start_tor_daemon()
    except Exception:
        pass

# Getting the chat server
while True:
    clear_console()
    print("(Example: 4ryc2mpb67ciikwumutb47xgt7fxrnuek5xe62kx6dgdbemr6kbwxx47.onion)")
    service_address = input(
        "Enter the URL of the CipherChat Tor Hidden Service: ")

    if not re.match(r"^[a-z2-7]{56}\.onion$", service_address):
        print("[Error] You have not given a valid Onion address")
        input("Enter: ")
    else:
        print("Getting Tor Session...")
        session = Tor.get_request_session()
        print("Requesting Service Address...")
        start_time = time()
        response = session.get("http://" + service_address + "/ping")
        end_time = time()
        print("Request took", end_time-start_time, "s")
        try:
            response.raise_for_status()
            response_content = response.content.decode("utf-8")
        except Exception as e:
            print(f"[Error] Error while requesting the ChatServer: '{e}'")
            input("Enter:")
        else:
            shorten_response_content = shorten_text(response_content, 50)

            if not "Pong! CipherChat Chat Service " in response_content:
                print(
                    f"[Error] This service does not appear to be a CipherChat server. Server Response: '{shorten_response_content}'")
                input("Enter:")
            else:

                try:
                    SERVICE_VERSION = float(response_content.replace(
                        "Pong! CipherChat Chat Service ", ""))
                except Exception as e:
                    print(
                        f"[Error] This service does not appear to be a CipherChat server. Server Response: '{shorten_response_content}'")
                    input("Enter:")

                if SERVICE_VERSION != VERSION:
                    print("[Error] This service does not have the same version as you" +
                          f"Service Version: {SERVICE_VERSION}\nYour Version: {VERSION}")
                    input("Enter:")
                else:
                    SERVICE_ADDRESS = service_address
                    break
