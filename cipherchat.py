import os
import platform
from typing import Tuple, Optional, Union
import shutil
from sys import argv as ARGUMENTS, exit
from time import time
from rich.console import Console
from rich.progress import Progress
import stem
from stem import control
from stem.process import launch_tor_with_config
import requests
from bs4 import BeautifulSoup
import gnupg
import subprocess
import plistlib
from getpass import getpass
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import re
import json

VERSION = 1.3

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
TEMP_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "tmp")
KEY_FILE_PATH_CONF_PATH = os.path.join(DATA_DIR_PATH, "keyfile-path.conf")
PERSISTENT_STORAGE_CONF_PATH = os.path.join(NEEDED_DIR_PATH, "persistent-storage.conf")
SERVICES_CONF_PATH = os.path.join(NEEDED_DIR_PATH, "services.conf")

GUTMANN_PATTERNS = [bytes([i % 256] * 100000) for i in range(35)]
DOD_PATTERNS = [bytes([0x00] * 100000), bytes([0xFF] * 100000), bytes([0x00] * 100000)]

console = Console()


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


SYSTEM, MACHINE = get_system_architecture()

TOR_PATH = {"Windows": f"C:\\Users\\{os.environ.get('USERNAME')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"}.get(SYSTEM, "/usr/bin/tor")
TORRC_PATH = {"Windows": f"C:\\Users\\{os.environ.get('USERNAME')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\Tor\\torrc"}.get(SYSTEM, "/usr/local/etc/tor/torrc")
TOR_EXT = {"Windows": "exe"}.get(SYSTEM, "dmg")
KEYSERVER_URLS = ["hkp://keyserver.ubuntu.com:80","keys.gnupg.net", "pool.sks-keyservers.net", "pgp.mit.edu"]

FACTS = ["Tor is a valuable tool for activists, journalists, and individuals in countries with restricted internet access, allowing them to communicate and access information without fear of surveillance.", "The Tor Browser was first created by the U.S. Naval Research Laboratory.", "The name 'Tor' originally stood for 'The Onion Router', referring to its multiple layers of encryption, much like the layers of an onion.", "The Tor Browser is open-source software, which means its source code is freely available for anyone to inspect, modify, and contribute to.", "Tor is designed to prioritize user privacy by routing internet traffic through a network of volunteer-operated servers, making it difficult to trace the origin and destination of data.",
         "The development of Tor has received funding from various government agencies, including the U.S. government, due to its importance in promoting online privacy and security.", "Tor allows websites to operate as hidden services, which are only accessible through the Tor network. This has led to the creation of websites that can't be easily traced or taken down.", "Websites on the Tor network often have addresses ending in '.onion' instead of the usual '.com' or '.org', adding to the uniqueness of the network.", "The strength of the Tor network lies in its thousands of volunteer-run relays worldwide. Users' data is passed through multiple relays, making it extremely difficult for anyone to trace their online activities."]


def clear_console():
    "Cleans the console and shows logo"

    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)


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


if "-a" in ARGUMENTS or "--about" in ARGUMENTS:
    clear_console()
    print(f"Current version: {VERSION}")
    print("CipherChat is used for secure chatting with end to end encryption and anonymous use of the Tor network for sending / receiving messages, it is released under the GPL v3 on Github. Setting up and using secure chat servers is made easy.")
    print("Use `python cipherchat.py -h` if you want to know all commands. To start use `python cipherchat.py`.")
    exit(0)


if "-k" in ARGUMENTS or "--killswitch" in ARGUMENTS:
    clear_console()
    start_time = time()
    with console.status("[bold green]All files will be overwritten and deleted several times... (This can take several seconds)"):
        if os.path.isdir(DATA_DIR_PATH):
            SecureDelete.directory(DATA_DIR_PATH)
    end_time = time()
    console.log("[green]Completed, all files are irrevocably deleted.","(took", end_time - start_time, "s)")
    exit(0)


if "-h" in ARGUMENTS or "--help" in ARGUMENTS:
    clear_console()
    print("> To start the client, simply do not use any arguments.")
    print("-h, --help                  Displays this help menu.")
    print("-a, --about                 Displays an About Cipherchat overview")
    print("-k, --killswitch            Immediately deletes all data in the data Dir and thus all persistent user data")
    print("-t, --torhiddenservice      Launches a CipherChat Tor Hidden Service")
    exit(0)


class Tor:
    """
    Collection of functions that have something to do with the Tor network
    """

    def get_download_link():
        "Request https://www.torproject.org to get the latest download links"

        response = requests.get("https://www.torproject.org/download/")
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        anchors = soup.find_all('a')

        download_url = None
        signature_url = None

        for anchor in anchors:
            href = anchor.get('href')

            if href:
                if "/dist/torbrowser/" in href:
                    if SYSTEM.lower() in href:
                        if href.endswith(".asc"):
                            signature_url = "https://www.torproject.org" + href
                        else:
                            download_url = "https://www.torproject.org" + href
        
        return (download_url, signature_url)

    def get_key_name():
        "Finds out the KEY Name from the Tor Project"

        gpg = gnupg.GPG()

        search_result = gpg.search_keys("Tor Browser Developers (signing key) <torbrowser@torproject.org>", keyserver=KEYSERVER_URLS[0])

        if search_result:
            key = search_result[0]
            key_name = key['keyid']

            return key_name

        raise Exception("[Error] No keyname found for The Onion Router, the keyname is needed to verify the download file, Download Canceled.")
    
    def get_public_key(key_name: str) -> gnupg.GPG:
        """
        Creates a PGP instance, and downloads Public Keys
        
        :param key_name: The Key Name from the Tor project
        """

        gpg = gnupg.GPG()

        for keyserver_url in KEYSERVER_URLS:
            try:
                gpg.recv_keys(keyserver_url, key_name, timeout = 15)
            except:
                console.log(f"[red]Failed to download the public key from the KeyServer `{keyserver_url}`")
            else:
                console.log(f"[green]Loaded Key from `{keyserver_url}`")

        return gpg

    def start_tor_daemon():
        "Launches The Onion Router Daemom"

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


def download_file(url, to, name):
    progress = Progress()

    with progress:
        task = progress.add_task(f"[cyan]Downloading {name}...", total=100)
        downloaded_bytes = 0

        with open(to, 'wb') as file:
            response = requests.get(url, stream=True)

            if response.status_code == 200:
                total_length = int(response.headers.get('content-length'))

                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)

                        downloaded_bytes += len(chunk)
                        percent_complete = (downloaded_bytes / total_length) * 100

                        progress.update(task, completed=percent_complete + 1)


clear_console()

# Install The Onion Router
if os.path.isfile(TOR_PATH):
    console.log("[green]The Onion Router exists")
else:
    if SYSTEM == "Linux":
        raise Exception("[Error] The Tor Browser is not installed and cannot be installed by python on Linux, just use your package manager with `tor` as package to install The Onion Router.")
    elif SYSTEM in ["Windows", "macOS"]:
        with console.status("[bold green]Trying to get the download links for Tor..."):
            download_link, signature_link = Tor.get_download_link()
        
        if download_link is None:
            raise Exception("[Error] Tor Browser could not be installed on your operating system, install it manually at https://www.torproject.org/download/ ")
        console.log("[green]~ Downloaded Tor Links")
        
        if not os.path.isdir(TEMP_DIR_PATH):
            os.mkdir(TEMP_DIR_PATH)

        installation_file_path = os.path.join(TEMP_DIR_PATH, "torbrowser." + TOR_EXT)
        signature_file_path = os.path.join(TEMP_DIR_PATH, "signature.asc")

        download_file(download_link, installation_file_path, "Tor Browser")

        download_file(signature_link, signature_file_path, "Tor Browser Signature")

        with console.status("[bold green]Trying to get the PGP Key Name for The Onion Router..."):
            key_name = Tor.get_key_name()
        console.log("[green]~ Key Name received")
        
        with console.status("[bold green]Loading the Public Keys for The Onion Router..."):
            gpg = Tor.get_public_key(key_name)
        console.log("[green]~ Public Keys Loaded")

        with console.status("[bold green]Verify The Onion Router Installation File..."):
            with open(signature_file_path, 'rb') as signature_file:
                verification = gpg.verify_file(signature_file, installation_file_path)
        
        if verification.valid:
            console.log("[green]~ The signature is valid")
        else:
            raise Exception("[Error] The signature does not seem to be valid, which may be due to The Onion Router installation file not being downloaded properly or torproject.org being infected.")

        with console.status("[bold green]Installation file opened, waiting for the installation wizard to finish..."):
            if SYSTEM == "Windows":
                installation_process = subprocess.Popen([installation_file_path])
                installation_process.wait()
            else:
                mount_info = subprocess.check_output(["hdiutil", "attach", "-plist", installation_file_path])
                mount_info = mount_info.decode("utf-8")

                mount_info_dict = plistlib.loads(mount_info)
                mount_point = mount_info_dict["system-entities"][0]["mount-point"]

                subprocess.run(["cp", "-R", f"{mount_point}/Tor.app", "/Applications"])

                subprocess.run(["hdiutil", "detach", mount_point])
        console.log("[green]The Hidden Router Installation Completed")

        with console.status("[bold green]Cleaning up (This can take up to two minutes)..."):
            SecureDelete.directory(TEMP_DIR_PATH)


if "-t" in ARGUMENTS or "--torhiddenservice" in ARGUMENTS:
    raise Exception 


# Use Persistent Storage?
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
                    keep_input = input("Your password is insecure, enter k to keep it: ")
                    if not keep_input.lower() in ["k", "keep"]:
                        KEEP = False
                    else:
                        print("")

                if KEEP:
                    repeat_master_password = getpass("Please repeat your master password: ")
                    if not repeat_master_password == master_password:
                        print("[Error] The passwords do not match.")
                        input("Enter: ")
                    else:
                        break

        # Get Key File Path
        while True:
            clear_console()
            keyfile_path = input("Enter a folder where the keyfile should be saved or Enter: ")

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

        with console.status("[bold green]Encrypting the Key File path..."):
            crypted_key_file_path = SymmetricEncryption(master_password).encrypt(KEY_FILE_PATH)

        with console.status("[bold green]Saving the Key File path..."):
            with open(KEY_FILE_PATH_CONF_PATH, "w", encoding="utf-8") as writeable_file:
                writeable_file.write(crypted_key_file_path)

    # Get Secret Key
    if not os.path.isfile(KEY_FILE_PATH):
        with console.status("[bold green]Generate Secret Key..."):
            SECRET_KEY = generate_random_string(512)

        with console.status("[bold green]Encrypt Secret Key with Password..."):
            crypted_secret_key = SymmetricEncryption(master_password).encrypt(SECRET_KEY)

        with console.status("[bold green]Saving the Secret Key..."):
            with open(KEY_FILE_PATH, "w", encoding="utf-8") as writeable_file:
                writeable_file.write(crypted_secret_key)
    else:
        with console.status("[bold green]Loading the Encrypted Secret Key..."):
            with open(KEY_FILE_PATH, "r", encoding="utf-8") as readable_file:
                crypted_secret_key = readable_file.read()

        with console.status("[bold green]Decrypting the Secret Key..."):
            SECRET_KEY = SymmetricEncryption( master_password).decrypt(crypted_secret_key)

    PASSKEY = master_password + SECRET_KEY

clear_console()

# Check and start The Onion Router Daemon
is_alive = False
with console.status("[bold green]Getting whether Tor Daemon is alive..."):
    try:
        is_alive = Tor.is_tor_daemon_alive()
    except:
        pass

if not is_alive:
    with console.status("[bold green]Try to start the Tor Daemon..."):
        Tor.start_tor_daemon()


def shorten_text(text: str, length: int) -> str:
    """
    Function to shorten the text and append "...".

    :param text: The text to be shortened
    :param length: The length of the text
    """

    if len(text) > length:
        text = text[:length] + "..."
    return text


# Getting the chat server
while True:
    clear_console()
    print("(Example: 4ryc2mpb67ciikwumutb47xgt7fxrnuek5xe62kx6dgdbemr6kbwxx47.onion)")
    service_address = input("Enter the URL of the CipherChat Tor Hidden Service: ")

    if not re.match(r"^[a-z2-7]{56}\.onion$", service_address):
        print("[Error] You have not given a valid Onion address")
        input("Enter: ")
    else:
        with console.status("[bold green]Getting Tor Session..."):
            session = Tor.get_request_session()

        start_time = time()
        with console.status("[bold green]Requesting Service Address..."):
            response = session.get("http://" + service_address + "/ping")
        end_time = time()

        console.log("[green]Request took", end_time-start_time, "s")
        try:
            response.raise_for_status()
            response_content = response.content.decode("utf-8")
        except Exception as e:
            print(f"[Error] Error while requesting the ChatServer: '{e}'")
            input("Enter:")
        else:
            shorten_response_content = shorten_text(response_content, 50)

            if not "Pong! CipherChat Chat Service " in response_content:
                print(f"[Error] This service does not appear to be a CipherChat server. Server Response: '{shorten_response_content}'")
                input("Enter:")
            else:

                try:
                    SERVICE_VERSION = float(response_content.replace("Pong! CipherChat Chat Service ", ""))
                except Exception as e:
                    print(f"[Error] This service does not appear to be a CipherChat server. Server Response: '{shorten_response_content}'")
                    input("Enter:")

                if SERVICE_VERSION != VERSION:
                    print("[Error] This service does not have the same version as you" +
                          f"Service Version: {SERVICE_VERSION}\nYour Version: {VERSION}")
                    input("Enter:")
                else:
                    SERVICE_ADDRESS = service_address
                    break


SAVED_SERVICES = None
SAVED_SERVICE = None
SERVICE_ACCOUNT_NAME = None
SERVICE_ACCOUNT_PASSWORD = None


# Check if account name or password is stored and if service already has cache data
if USE_PERSISTENT_STORAGE:
    if os.path.isfile(SERVICES_CONF_PATH):
        with console.status("[bold green]Loading stored data for all services..."):
            with open(SERVICES_CONF_PATH, "r") as readable_file:
                crypted_services = readable_file.read()
        with console.status("[bold green]Decrypting stored data for all services..."):
            try:
                SAVED_SERVICES = json.loads(SymmetricEncryption(PASSKEY).decrypt(crypted_services))
            except Exception as e:
                print(f"[Error] Error while decrypting the services: '{e}'")
        if SAVED_SERVICES:
            if SAVED_SERVICES.get(SERVICE_ADDRESS):
                SAVED_SERVICE = SAVED_SERVICES.get(SERVICE_ADDRESS)
    
    if SAVED_SERVICE:
        SERVICE_ACCOUNT_NAME = SAVED_SERVICE["name"]
        SERVICE_ACCOUNT_PASSWORD = SAVED_SERVICE["password"]

service_action = None

if SERVICE_ACCOUNT_NAME:
    service_action = "login"


# Get Action, Login or Register?
while not service_action:
    clear_console()

    print(f"Connected to `{service_address}`")
    input_service_action = input("l - Log in or r - Register: ")

    if input_service_action.lower() in ["l", "login", "log in"]:
        service_action = "login"
    elif input_service_action.lower() in ["r", "register"]:
        service_action = "register"
    else:
        print("[Error] Incorrect arguments entered.")
        input("Enter: ")

