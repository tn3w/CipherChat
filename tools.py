from rich.console import Console
import platform
from typing import Tuple, Optional, Union
import os
import shutil
import requests
from bs4 import BeautifulSoup
import re
import gnupg
import psutil
from stem.process import launch_tor_with_config
from stem import control
import stem
from rich.progress import Progress
import secrets
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding


LOGO = '''
 dP""b8 88 88""Yb 88  88 888888 88""Yb  dP""b8 88  88    db    888888 
dP   `" 88 88__dP 88  88 88__   88__dP dP   `" 88  88   dPYb     88   
Yb      88 88"""  888888 88""   88"Yb  Yb      888888  dP__Yb    88   
 YboodP 88 88     88  88 888888 88  Yb  YboodP 88  88 dP""""Yb   88   

-~-    Programmed by TN3W - https://github.com/tn3w/CipherChat    -~-
'''

KEYSERVER_URLS = ["hkp://keyserver.ubuntu.com:80", "keys.gnupg.net", "pool.sks-keyservers.net", "pgp.mit.edu"]

console = Console()

GUTMANN_PATTERNS = [bytes([i % 256] * 100000) for i in range(35)]
DOD_PATTERNS = [bytes([0x00] * 100000), bytes([0xFF] * 100000), bytes([0x00] * 100000)]

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


def clear_console():
    "Cleans the console and shows logo"

    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)


def download_file(url: str, save_path: str, operation_name: Optional[str] = None) -> None:
    """
    Function to download a file

    :param url: The url of the file
    :param save_path: Specifies where to save the file
    :param operation_name: Sets the name of the operation in the console (Optional)
    """

    progress = Progress()

    with progress:
        if operation_name:
            task = progress.add_task(f"[cyan]Downloading {operation_name}...", total=100)
        else:
            task = progress.add_task(f"[cyan]Downloading...", total=100)

        downloaded_bytes = 0

        with open(save_path, 'wb') as file:
            response = requests.get(url, stream=True)

            if response.status_code == 200:
                total_length = int(response.headers.get('content-length'))

                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)

                        downloaded_bytes += len(chunk)
                        percent_complete = (downloaded_bytes / total_length) * 100

                        progress.update(task, completed=percent_complete + 1)


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


def generate_random_string(length: int, with_punctuation: bool = True, with_letters: bool = True) -> str:
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


def is_password_save(password: str) -> Tuple[bool, Optional[str]]:
    """
    Function to check passwords

    :param password: The password to check
    """
    if len(password) < 12:
        return False, "[Error] Master password must consist of at least 12 characters (a good password usually has 16 characters)"
    elif not re.search(r'[A-Z]', password):
        return False, "[Error] Your password does not contain a capital letter."
    elif not re.search(r'[a-z]', password):
        return False, "[Error] Your password does not contain a lowercase letter."
    elif not re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', password):
        return False, "[Error] Your password does not contain any special characters."
    return True, None


def shorten_text(text: str, length: int) -> str:
    """
    Function to shorten the text and append "...".

    :param text: The text to be shortened
    :param length: The length of the text
    """

    if len(text) > length:
        text = text[:length] + "..."
    return text


class SecureDelete:
    "Class for secure deletion of files or folders"

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

class Tor:
    "Collection of functions that have something to do with the Tor network"

    def get_download_link() -> Tuple[Optional[str], Optional[str]]:
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

    def get_key_name() -> str:
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

        with console.status("[bold green]Loading the Public Keys for The Onion Router..."):
            for keyserver_url in KEYSERVER_URLS:
                try:
                    gpg.recv_keys(keyserver_url, key_name)
                except TimeoutError:
                    console.log(f"[red]Failed to download the public key from the KeyServer `{keyserver_url}`")
                else:
                    console.log(f"[green]Loaded Key from `{keyserver_url}`")

        return gpg

    def kill_tor_daemon() -> None:
        "Stops all running Tor Daemon processes."

        with console.status("[red]Killing Tor Daemon..."):
            try:
                for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
                    try:
                        if "tor" in process.cmdline():
                            process.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                console.log("[green]All Tor Daemon processes stopped.")
            except Exception as e:
                console.log(f"[red]Error stopping Tor Daemon: {e}")

    def start_tor_daemon() -> None:
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
            
    def start_tor_service(hidden_service_dir: str, hidden_service_port: int) -> None:
        """
        Starts the Onion Router with Hidden Service Configuration

        :param hidden_service_dir: Directory to the Hidden Service
        :param hidden_service_port: To which port The Onion Router should listen
        """

        if not Tor.is_tor_daemon_alive():
            launch_tor_with_config(
                tor_cmd=TOR_PATH,
                config={
                    'SocksPort': '9050',
                    'ControlPort': '9051',
                    'HiddenServiceDir': hidden_service_dir,
                    'HiddenServicePort': f'80 127.0.0.1:{hidden_service_port}',
                }
            )

    def is_tor_daemon_alive() -> bool:
        "Function to check if the Tor Daemon is currently running"

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
        "Creates gate connection and returns requests.session"

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

class Hashing:
    "Implementation of secure hashing with SHA256 and 200000 iterations"

    def __init__(self, salt: Optional[str] = None, without_salt: bool = False):
        """
        :param salt: The salt, makes the hashing process more secure (Optional)
        :param without_salt: If True, no salt is added to the hash
        """

        self.salt = salt
        self.without_salt = without_salt

    def hash(self, plain_text: str, hash_length: int = 32) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        plain_text = str(plain_text).encode('utf-8')

        if not self.without_salt:
            salt = self.salt
            if salt is None:
                salt = secrets.token_bytes(32)
            else:
                if not isinstance(salt, bytes):
                    try:
                        salt = bytes.fromhex(salt)
                    except:
                        salt = salt.encode('utf-8')
        else:
            salt = None

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=hash_length,
            salt=salt,
            iterations=200000,
            backend=default_backend()
        )

        hashed_data = kdf.derive(plain_text)

        if not self.without_salt:
            hash = b64encode(hashed_data).decode('utf-8') + "//" + salt.hex()
        else:
            hash = b64encode(hashed_data).decode('utf-8')

        return hash

    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """
        
        if not self.without_salt:
            salt = self.salt
            if "//" in hash:
                hash, salt = hash.split("//")
            
            if salt is None:
                raise ValueError("Salt cannot be None if there is no salt in hash")

            salt = bytes.fromhex(salt)
        else:
            salt = None

        hash_length = len(b64decode(hash))

        comparison_hash = Hashing(salt=salt, without_salt = self.without_salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash


class SymmetricEncryption:
    "Implementation of symmetric encryption with AES"

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
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
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
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()


class AsymmetricEncryption:
    "Implementation of secure asymmetric encryption with RSA"

    def __init__(self, public_key: Optional[str] = None, private_key: Optional[str] = None):
        """
        :param public_key: The public key to encrypt a message / to verify a signature
        :param private_key: The private key to decrypt a message / to create a signature
        """
        
        self.public_key, self.private_key = public_key, private_key

        if not public_key is None:
            self.publ_key = serialization.load_der_public_key(b64decode(public_key), backend=default_backend())
        else:
            self.publ_key = None

        if not private_key is None:
            self.priv_key = serialization.load_der_private_key(b64decode(private_key), password=None, backend=default_backend())
        else:
            self.priv_key = None

    def generate_keys(self, key_size: int = 2048) -> "AsymmetricEncryption":
        """
        Generates private and public key

        :param key_size: The key size of the private key
        """
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.private_key = b64encode(self.priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode('utf-8')
        
        self.publ_key = self.priv_key.public_key()
        self.public_key = b64encode(self.publ_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')

        return self

    def encrypt(self, plain_text: str) -> Tuple[str, str]:
        """
        Encrypt the provided plain_text using asymmetric and symmetric encryption

        :param plain_text: The text to be encrypted
        """

        if self.publ_key is None:
            raise ValueError("The public key cannot be None in encode, this error occurs because no public key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        symmetric_key = secrets.token_bytes(64)

        cipher_text = SymmetricEncryption(symmetric_key).encrypt(plain_text)

        encrypted_symmetric_key = self.publ_key.encrypt(
            symmetric_key,
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm = hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        encrypted_key = b64encode(encrypted_symmetric_key).decode('utf-8')
        return f"{encrypted_key}//{cipher_text}", b64encode(symmetric_key).decode('utf-8')

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypt the provided cipher_text using asymmetric and symmetric decryption

        :param cipher_text: The encrypted message with the encrypted symmetric key
        """

        if self.priv_key is None:
            raise ValueError("The private key cannot be None in decode, this error occurs because no private key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        encrypted_key, cipher_text = cipher_text.split("//")[0], cipher_text.split("//")[1]
        encrypted_symmetric_key = b64decode(encrypted_key.encode('utf-8'))

        symmetric_key = self.priv_key.decrypt(
            encrypted_symmetric_key, 
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        plain_text = SymmetricEncryption(symmetric_key).decrypt(cipher_text)

        return plain_text

    def sign(self, plain_text: Union[str, bytes]) -> str:
        """
        Sign the provided plain_text using the private key

        :param plain_text: The text to be signed
        """

        if self.priv_key is None:
            raise ValueError("The private key cannot be None in sign, this error occurs because no private key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        if isinstance(plain_text, str):
            plain_text = plain_text.encode()

        signature = self.priv_key.sign(
            plain_text,
            asy_padding.PSS(
                mgf = asy_padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length = asy_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return b64encode(signature).decode('utf-8')

    def verify_sign(self, signature: str, plain_text: Union[str, bytes]) -> bool:
        """
        Verify the signature of the provided plain_text using the public key

        :param sign_text: The signature of the plain_text with base64 encoding
        :param plain_text: The text whose signature needs to be verified
        """

        if self.publ_key is None:
            raise ValueError("The public key cannot be None in verify_sign, this error occurs because no public key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        if isinstance(plain_text, str):
            plain_text = plain_text.encode()

        signature = b64decode(signature)

        try:
            self.publ_key.verify(
                signature,
                plain_text,
                asy_padding.PSS(
                    mgf = asy_padding.MGF1(
                        hashes.SHA256()
                    ),
                    salt_length = asy_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True
        except Exception:
            return False
