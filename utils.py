import threading
from typing import Tuple, Optional, Union
import os
import distro
import shutil
import requests
import subprocess
from bs4 import BeautifulSoup
import re
import socket
import gnupg
import psutil
import json
import rarfile
from stem.process import launch_tor_with_config
from stem import control
import stem
from rich.progress import Progress
import secrets
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from jinja2 import Environment, select_autoescape, Undefined
from captcha.image import ImageCaptcha
from cons import LOGO, NEEDED_DIR_PATH, DOD_PATTERNS, GUTMANN_PATTERNS, CONSOLE, DISTRO_TO_PACKAGE_MANAGER, PACKAGE_MANAGERS,\
    GNUPG_PATH, KEYSERVER_URLS, TEMP_DIR_PATH, DOWNLOAD_BRIDGE_URLS, IP_VERSIONS, BRIDGES_CONF_PATH, DEFAULT_BRIDGES_CONF,\
    SNOWFLAKE_BUILDIN_BRIDGES, WEBTUNNEL_BUILDIN_BRIDGES, MEEKLITE_BUILDIN_BRIDGES, OBFS4_BUILDIN_BRIDGES, SYSTEM, SERVICE_SETUP_CONF_PATH,\
    DEFAULT_HIDDEN_SERVICE_DIR_PATH, TOR_PATH, USERS_HIDDEN_SERVICE_PATH, SOCKS_PORT, CONTROLLER_PORT


def clear_console():
    "Cleans the console and shows logo"

    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)


def download_file(url: str, save_path: str, operation_name: Optional[str] = None) -> bool:
    """
    Function to download a file

    :param url: The url of the file
    :param save_path: Specifies where to save the file
    :param operation_name: Sets the name of the operation in the console (Optional)
    """

    progress = Progress()

    with progress:

        downloaded_bytes = 0

        with open(save_path, 'wb') as file:
            try:
                response = requests.get(url, stream=True)
            except:
                return False

            if response.status_code == 200:
                total_length = int(response.headers.get('content-length'))

                if operation_name:
                    task = progress.add_task(f"[cyan]Downloading {operation_name}...", total=total_length)
                else:
                    task = progress.add_task(f"[cyan]Downloading...", total=total_length)

                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)
                        downloaded_bytes += len(chunk)

                        progress.update(task, completed=downloaded_bytes)
            else:
                return False
    return True


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
    
    password_sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    hash_prefix = password_sha1_hash[:5]
    
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{hash_prefix}")
    except:
        pass
    else:
        if response.status_code == 200:
            response_content = response.text

            for sha1_hash in response_content.split("\n"):
                sha1_hash = sha1_hash.split(":")[0]
                if sha1_hash == password_sha1_hash:
                    return False, "[Error] Your password was found in a data leak."

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


file_locks = dict()


class JSON:
    "Class for loading / saving JavaScript Object Notation (= JSON)"

    @staticmethod
    def load(file_name: str, default: Union[dict, list] = dict()) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if not os.path.isfile(file_name):
            return default
        
        if file_name not in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, "r") as file:
                data = json.load(file)
            return data
    
    @staticmethod
    def dump(data: Union[dict, list], file_name: str) -> None:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_name: The file to save to
        """

        file_directory = os.path.dirname(file_name)
        if not os.path.isdir(file_directory):
            raise FileNotFoundError("Directory '" + file_directory + "' does not exist.")
        
        if file_name not in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, "w") as file:
                json.dump(data, file)


# Languages
LANGUAGES = JSON.load(os.path.join(NEEDED_DIR_PATH, "languages.json"), list())
LANGUAGE_CODES = [language["code"] for language in LANGUAGES]
TRANSLATIONS_PATH = os.path.join(NEEDED_DIR_PATH, "translations.json")


class SecureDelete:
    "Class for secure deletion of files or folders"

    @staticmethod
    def list_files_and_directories(directory_path: str) -> Tuple[list, list]:
        """
        Function to get all files and directorys in a directory

        :param directory_path: The path to the directory
        """

        all_files = list()
        all_directories = list()

        def list_files_recursive(root, depth):
            for item in os.listdir(root):
                item_path = os.path.join(root, item)
                if os.path.isfile(item_path):
                    all_files.append((item_path, depth))
                elif os.path.isdir(item_path):
                    all_directories.append((item_path, depth))
                    list_files_recursive(item_path, depth + 1)

        list_files_recursive(directory_path, 0)

        all_files.sort(key=lambda x: x[1], reverse=True)
        all_directories.sort(key=lambda x: x[1], reverse=True)

        all_files = [path for path, _ in all_files]
        all_directories = [path for path, _ in all_directories]

        return all_files, all_directories

    @staticmethod
    def file(file_path: str, semaphore: Optional[threading.Semaphore] = None, quite: bool = False) -> None:
        """
        Function to securely delete a file by replacing it first with random characters and then according to Gutmann patterns and DoD 5220.22-M patterns

        :param file_path: The path to the file
        :param semaphore: The Semaphore Object
        :param quite: If True nothing is written to the console
        """

        if semaphore is None:
            semaphore = threading.Semaphore()

        with semaphore:
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
                except Exception as e:
                    if not quite:
                        CONSOLE.log(f"[red][Error] Error deleting the file '{file_path}': {e}")

            try:
                os.remove(file_path)
            except:
                pass
    
    @staticmethod
    def directory(directory_path: str, quite: bool = False) -> None:
        """
        Securely deletes entire folders with files and subfolders

        :param directory_path: The path to the directory
        :param quite: If True nothing is written to the console
        """

        files, directorys = SecureDelete.list_files_and_directories(directory_path)
        
        semaphore = threading.Semaphore(20)

        for file in files:
            thread = threading.Thread(target=SecureDelete.file, args=(file, semaphore, quite))
            thread.start()
        
        for directory in directorys:
            try:
                shutil.rmtree(directory)
            except:
                pass
        
        try:
            shutil.rmtree(directory_path)
        except:
            pass


class Linux:
    "Collection of functions that have something to do with Linux"

    @staticmethod
    def get_package_manager() -> Tuple[Optional[str], Optional[str]]:
        "Returns the Packet Manager install command and the update command"

        distro_id = distro.id()

        package_manager = DISTRO_TO_PACKAGE_MANAGER.get(distro_id, {"installation_command": None, "update_command": None})

        installation_command, update_command = package_manager["installation_command"], package_manager["update_command"]
        
        if None in [installation_command, update_command]:
            for package_manager in PACKAGE_MANAGERS:
                try:
                    subprocess.check_call(package_manager["version_command"], shell=True)
                except:
                    pass
                else:
                    installation_command, update_command = package_manager["installation_command"], package_manager["update_command"]
        
        return installation_command, update_command
    
    @staticmethod
    def install_package(package_name: str) -> None:
        """
        Attempts to install a Linux package
        
        :param package_name: Name of the Linux packet
        """
        
        with CONSOLE.status("[green]Trying to get package manager..."):
            installation_command, update_command = Linux.get_package_manager()
        CONSOLE.log(f"[green]~ Package Manager is `{installation_command.split(' ')[0]}`")

        if not None in [installation_command, update_command]:
            try:
                update_process = subprocess.Popen("sudo " + update_command, shell=True)
                update_process.wait()
            except Exception as e:
                CONSOLE.log(f"[red]Error using update Command while installing linux package '{package_name}': '{e}'")
            
            install_process = subprocess.Popen(f"sudo {installation_command} {package_name} -y", shell=True)
            install_process.wait()
        
        else:
            CONSOLE.log("[red]No packet manager found for the current Linux system, you seem to use a distribution we don't know?")
            raise Exception("No package manager found!")

        return None


class GnuPG:
    "Collection of functions that have something to do with GNUPG"

    @staticmethod
    def search_key_name(search: str) -> Optional[str]:
        """
        Finds out the KEY Name based on a search term
        
        :param search: Search term
        """

        try:
            gpg = gnupg.GPG()
        except RuntimeError as e:
            if os.path.isfile(GNUPG_PATH):
                gpg = gnupg.GPG(binary = GNUPG_PATH)
            else:
                return None

        search_result = gpg.search_keys(search, keyserver=KEYSERVER_URLS[0])

        if search_result:
            key = search_result[0]
            key_name = key['keyid']

            return key_name

        raise Exception("[Error] No keyname found for The Onion Router, the keyname is needed to verify the download file, Download Canceled.")
    
    @staticmethod
    def load_public_keys(key_name: str) -> Optional[gnupg.GPG]:
        """
        Creates a PGP instance, and downloads Public Keys
        
        :param key_name: The Key Name
        """

        try:
            gpg = gnupg.GPG()
        except:
            if os.path.isfile(GNUPG_PATH):
                gpg = gnupg.GPG(binary=GNUPG_PATH)
            else:
                return None

        with CONSOLE.status("[bold green]Loading the Public Keys for The Onion Router..."):
            for keyserver_url in KEYSERVER_URLS:
                try:
                    gpg.recv_keys(keyserver_url, key_name)
                except TimeoutError:
                    CONSOLE.log(f"[red]Failed to download the public key from the KeyServer `{keyserver_url}`")
                else:
                    CONSOLE.log(f"[green]Loaded Key from `{keyserver_url}`")

        return gpg


class Tor:
    "Collection of functions that have something to do with the Tor network"

    @staticmethod
    def download_bridges() -> None:
        "Downloads Tor bridges obsf4, snowflake and webtunnel"

        if not os.path.isdir(TEMP_DIR_PATH):
            os.mkdir(TEMP_DIR_PATH)
        
        for bridge_type, download_urls in DOWNLOAD_BRIDGE_URLS.items():
            if bridge_type == "snowflake":
                index = 0
                for ip_version in IP_VERSIONS:
                    file_path = os.path.join(TEMP_DIR_PATH, bridge_type + ip_version + ".rar")

                    is_successful = download_file(download_urls["github"][index], file_path, bridge_type.title() + " " + ip_version.title())
                    if not is_successful:
                        download_file(download_urls["backup"][index], file_path, bridge_type.title() + " " + ip_version.title() + " Backup")

                    index = 1
            else:
                file_path = os.path.join(TEMP_DIR_PATH, bridge_type + ".txt")

                is_successful = download_file(download_urls["github"], file_path, bridge_type.title())
                if not is_successful:
                    download_file(download_urls["backup"], file_path, bridge_type.title() + " Backup")
    
    @staticmethod
    def process_bridges() -> None:
        "Processes and validates the downloaded bridges"

        if not os.path.isdir(NEEDED_DIR_PATH):
            os.mkdir(NEEDED_DIR_PATH)

        for bridge_type, _ in DOWNLOAD_BRIDGE_URLS.items():
            save_path = os.path.join(NEEDED_DIR_PATH, bridge_type + ".json")
            
            if bridge_type == "snowflake":
                snowflake_ips = list()
                for ip_version in IP_VERSIONS:
                    file_path = os.path.join(TEMP_DIR_PATH, bridge_type + ip_version + ".rar")

                    if not os.path.isfile(file_path):
                        continue

                    with rarfile.RarFile(file_path) as rf:
                        file_in_rar = rf.namelist()[0]

                        with rf.open(file_in_rar) as readable_file:
                            ips = readable_file.read().decode('utf-8')
                    
                    _ips = list()
                    for ip in ips.split("\n"):
                        ip = ip.strip()
                        if not ip == "":
                            _ips.append(ip)
                    
                    if {"ipv4": 1610000}.get(ip_version, 1190000) >= len(_ips):
                        continue

                    snowflake_ips.extend(_ips)
                
                if len(snowflake_ips) != 0:
                    with open(save_path, "w") as writeable_file:
                        json.dump(snowflake_ips, writeable_file)
            else:
                file_path = os.path.join(TEMP_DIR_PATH, bridge_type + ".txt")

                if os.path.isfile(file_path):
                    with open(file_path, "r") as readable_file:
                        ips = readable_file.read()

                    _ips = list()
                    for ip in ips.split("\n"):
                        ip = ip.strip()
                        if not ip == "":
                            _ips.append(ip)

                    if {"obfs4": 5000}.get(bridge_type, 20) >= len(_ips):
                        continue

                    with open(save_path, "w") as writeable_file:
                        json.dump(_ips, writeable_file)
    
    @staticmethod
    def get_bridge_configuration() -> Tuple[bool, str]:
        "Function that returns the bridge configuration"

        if os.path.isfile(BRIDGES_CONF_PATH):
            with open(BRIDGES_CONF_PATH, "r") as readable_file:
                bridges_configuration = readable_file.read().strip()
            
            try:
                bridge_conf = bridges_configuration.split("-")
                use_build_in, type_of_bridge = {"True": True}.get(bridge_conf[0], False), {"snowflake": "snowflake", "webtunnel": "webtunnel", "meek_lite": "meek_lite"}.get(bridge_conf[1], "obfs4")
                return use_build_in, type_of_bridge
            except:
                pass
        return DEFAULT_BRIDGES_CONF

    @staticmethod
    def get_bridges() -> Union[list, str]:
        "Function that returns bridges"

        use_build_in, type_of_bridge = Tor.get_bridge_configuration()
        bridges_needed = {"meek_lite": 1, "webtunnel": 1}.get(type_of_bridge, 3)
        buildin_list = {"snowflake": SNOWFLAKE_BUILDIN_BRIDGES, "webtunnel": WEBTUNNEL_BUILDIN_BRIDGES, "meek_lite": MEEKLITE_BUILDIN_BRIDGES}.get(type_of_bridge, OBFS4_BUILDIN_BRIDGES)

        bridges = list()
        
        while True:
            if len(buildin_list) == 1:
                bridges.append(buildin_list[0])
                break
            else:
                new_bridge = secrets.choice(buildin_list)
                if not new_bridge in bridges:
                    bridges.append(new_bridge)

            if len(bridges) >= bridges_needed:
                break


        if not use_build_in and not type_of_bridge == "meek_lite":
            file_path = os.path.join(NEEDED_DIR_PATH, type_of_bridge + ".json")
            file_bridges = JSON.load(file_path, [])
            
            bridges = list()

            while True:
                new_bridge = secrets.choice(file_bridges)
                if type_of_bridge == "snowflake":
                    new_bridge = "snowflake " + new_bridge

                if not new_bridge in bridges:
                    bridges.append(new_bridge)

                if len(bridges) >= bridges_needed:
                    break
        
        if len(bridges) == 1:
            bridges = bridges[0]
        
        return bridges

    @staticmethod
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

    @staticmethod
    def kill_tor_daemon() -> None:
        "Stops all running Tor Daemon processes."

        try:
            with control.Controller.from_port(port=CONTROLLER_PORT) as controller:
                controller.authenticate()
                controller.signal(stem.Signal.SHUTDOWN)
        except:
            pass
        else:
            return

        try:
            for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
                if "tor" in process.cmdline():
                    process.terminate()
            CONSOLE.log("[green]All Tor Daemon processes stopped.")
        except psutil.AccessDenied as e:
            CONSOLE.log(f"[red]Privileg Error: AccessDenied while stopping Tor: {e}")
        except Exception as e:
            CONSOLE.log(f"[red]Error stopping Tor Daemon: {e}")
    
    @staticmethod
    def at_exit_kill_tor(tor_process):
        "Kills the TOR process at the end"
        
        with CONSOLE.status("[bold green]Try to terminate the Tor process..."):
            tor_process.terminate()
            Tor.kill_tor_daemon()

    @staticmethod
    def get_hidden_service_info() -> (Optional[str], int):
        "Retrieves hidden service information from a configuration file."

        service_setup_info = JSON.load(SERVICE_SETUP_CONF_PATH)

        hidden_dir = service_setup_info.get("hidden_service_dir", None)
        hidden_port = service_setup_info.get("hidden_service_port", 8080)
        
        return hidden_dir, hidden_port

    @staticmethod
    def start_tor_daemon(as_service: bool = False) -> Optional[launch_tor_with_config]:
        """
        Launches The Onion Router Daemom
        
        :param as_service: If True, a hidden service is started with
        """

        if Tor.is_tor_daemon_running():
            Tor.kill_tor_daemon()

        if not as_service:
            bridges = Tor.get_bridges()

            if isinstance(bridges, list):
                bridge = secrets.choice(bridges)
            else:
                bridge = bridges

            config = {
                'SocksPort': str(SOCKS_PORT),
                'ControlPort': str(CONTROLLER_PORT),
                'Bridge': bridge
            }
        else:
            config = {
                'SocksPort': str(SOCKS_PORT),
                'ControlPort': str(CONTROLLER_PORT)
            }

        start_service_criterias = [os.path.isdir(DEFAULT_HIDDEN_SERVICE_DIR_PATH), os.path.isfile(SERVICE_SETUP_CONF_PATH), as_service]

        if any(start_service_criterias):
            hidden_dir, hidden_port = Tor.get_hidden_service_info()
            
            if (not hidden_dir and os.path.isdir(DEFAULT_HIDDEN_SERVICE_DIR_PATH)) or as_service:
                hidden_dir = DEFAULT_HIDDEN_SERVICE_DIR_PATH
            
            config['HiddenServiceDir'] = hidden_dir
            config['HiddenServicePort'] = f'80 127.0.0.1:{hidden_port}'

        try:
            tor_process = launch_tor_with_config(
                tor_cmd=TOR_PATH,
                config=config,
                take_ownership=True
            )
        except Exception as e:
            CONSOLE.log(f"[red][Error] Error when starting Tor: '{e}'")
            return None
        
        return tor_process
    
    @staticmethod
    def is_tor_controller_alive() -> bool:
        "Function to check if the Controller Port is alive"

        try:
            with control.Controller.from_port(port=CONTROLLER_PORT) as controller:
                controller.authenticate()

                if controller.is_alive():
                    return True
                else:
                    CONSOLE.log("[red][Error] Tor is probably not installed.")
        except (Exception) as socket_error:
            CONSOLE.log(f"[red][Error] Error connecting to the Tor Control Port '{socket_error}'")
        
        return False

    @staticmethod
    def is_tor_socks_alive() -> bool:
        "Function to check if the Socks Port is alive"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            sock.connect(("127.0.0.1", SOCKS_PORT))
        except Exception as e:
            CONSOLE.log(f"[red][Error] Error while connecting to Socks Port: `{e}`")
            return False
        finally:
            sock.close()
        
        return False

    @staticmethod
    def is_tor_daemon_running() -> bool:
        "Function to check if the Tor Daemon is currently running"
        
        for process in psutil.process_iter(attrs=['pid', 'name']):
            if 'tor' in process.name():
                return True
        
        return False

    @staticmethod
    def get_request_session() -> requests.session:
        "Creates gate connection and returns requests.session"

        def new_tor_signal():
            if secrets.choice([True, False, False, False, False, False, False, False]):
                with control.Controller.from_port(port=CONTROLLER_PORT) as controller:
                    controller.authenticate()
                    controller.signal(stem.Signal.NEWNYM)

        new_session = requests.session()

        try:
            new_tor_signal()
        except stem.SocketError:
            Tor.start_tor_daemon()
            new_tor_signal()
        except Exception as e:
            CONSOLE.log(f"[red][Error] Request Error: '{e}'")

        new_session.proxies = {
            'http': 'socks5h://127.0.0.1:' + str(SOCKS_PORT),
            'https': 'socks5h://127.0.0.1:' + str(SOCKS_PORT)
        }

        return new_session


class FastHashing:
    "Implementation for fast hashing"

    def __init__(self, salt: Optional[str] = None, without_salt: bool = False):
        """
        :param salt: The salt, makes the hashing process more secure (Optional)
        :param without_salt: If True, no salt is added to the hash
        """

        self.salt = salt
        self.without_salt = without_salt
    
    def hash(self, plain_text: str, hash_length: int = 8) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        if not self.without_salt:
            salt = self.salt
            if salt is None:
                salt = secrets.token_hex(hash_length)
            plain_text = salt + plain_text
        
        hash_object = hashlib.sha256(plain_text.encode())
        hex_dig = hash_object.hexdigest()
        
        if not self.without_salt:
            hex_dig += "//" + salt
        return hex_dig
    
    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """
        
        salt = None
        if not self.without_salt:
            salt = self.salt
            if "//" in hash:
                hash, salt = hash.split("//")
        
        hash_length = len(hash)

        comparison_hash = FastHashing(salt=salt, without_salt = self.without_salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash


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
            self.publ_key = serialization.load_der_public_key(public_key.encode('latin-1'), backend=default_backend())
        else:
            self.publ_key = None

        if not private_key is None:
            self.priv_key = serialization.load_der_private_key(private_key.encode('latin-1'), password=None, backend=default_backend())
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
        self.private_key = self.priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('latin-1')
        
        self.publ_key = self.priv_key.public_key()
        self.public_key = self.publ_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('latin-1')

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


class ArgumentValidator:
    "Contains functions for validating arguments and credentials"

    @staticmethod
    def username(username: Optional[str] = None, is_register: bool = True) -> Tuple[bool, Optional[dict]]:
        """
        Validates a username if it was specified, if its length is between 4 - 15, if it contains only the characters A-Z, a-z, 0-9, _ and if it already exists

        :param username: The username (Optional)
        :param is_register: If True, it is assumed that the given username should not exist yet.
        """

        if username is None:
            return False, {"status_code": 400, "error": "Parameter 'username' is None."}
        if len(username) < 4 or len(username) > 15:
            return False, {"status_code": 400, "error": "Parameter 'username' is to " + ("short" if len(username) < 4 else "long") + "."}
        if re.search(r"[^\w]", username):
            return False, {"status_code": 400, "error": "Parameter 'username' contains characters that do not belong in a username."}
        
        users = JSON.load(USERS_HIDDEN_SERVICE_PATH)

        for hashed_username, _ in users:
            comparison = FastHashing().compare(username, hashed_username)

            if comparison and is_register:
                return False, {"status_code": 400, "error": "The given username in Parameter 'username' exist."}
            
        if not is_register:
            return False, {"status_code": 400, "error": "The given username in Parameter 'username' does not exist."}
        
        return True, None
    
    @staticmethod
    def hashed_password(hashed_password: Optional[str] = None) -> Tuple[bool, Optional[dict]]:
        """
        Validates a password hash, whether it was specified, whether it has the correct length and whether it contains hash characters

        :param hashed_password: The hashed password (Optional)
        """

        if hashed_password is None:
            return False, {"status_code": 400, "error": "Parameter 'hashed_password' is None."}
        # hashed_password = Hashing().hash(password, hash_length=16)
        if len(hashed_password) != 90:
            return False, {"status_code": 400, "error": "Parameter 'hashed_password' has the wrong length."}
        if not re.match(r"^[\w+/]+=+\/\/[0-9a-fA-F]+$", hashed_password):
            return False, {"status_code": 400, "error": "Parameter 'hashed_password' contains characters that do not belong in a hash."}
        
        return True, None

    @staticmethod
    def hashed_chat_password(hashed_chat_password: Optional[str] = None) -> Tuple[bool, Optional[dict]]:
        """
        Validates a chat password hash, whether it has the correct length and whether it contains hash characters

        :param hashed_chat_password: The hashed password (Optional)
        """

        # hashed_chat_password = Hashing().hash(chat_password, hash_length=16)
        if len(hashed_chat_password) != 90:
            return False, {"status_code": 400, "error": "Parameter 'hashed_chat_password' has the wrong length."}
        if not re.match(r"^[\w+/]+=+\/\/[0-9a-fA-F]+$", hashed_chat_password):
            return False, {"status_code": 400, "error": "Parameter 'hashed_chat_password' contains characters that do not belong in a hash."}
        
        return True, None
    
    @staticmethod
    def public_key(public_key: Optional[str] = None) -> Tuple[bool, Optional[dict]]:
        """
        Validates a public key based on whether it was specified, its length, and whether it works

        :param public_key: The public key (Optional)
        """

        if public_key is None:
            return False, {"status_code": 400, "error": "Parameter 'public_key' is None."}
        if len(public_key) < 294 or len(public_key) > 550: # 2048 - 4096
            return False, {"status_code": 400, "error": "Parameter 'public_key' is to " + ("short" if len(public_key) < 294 else "long") + "."}
        try:
            serialization.load_der_public_key(public_key.encode('latin-1'), backend=default_backend())
        except:
            return False, {"status_code": 400, "error": "The public key given in the Parameter 'public_key' could not be loaded."}
        
        return True, None

    @staticmethod
    def crypted_private_key(crypted_private_key: Optional[str] = None) -> Tuple[bool, Optional[dict]]:
        """
        Validates a crypted_private_key if given, checks if the length is correct

        :param crypted_private_key: The crypted private key (Optional)
        """

        if crypted_private_key is None:
            return True, None
        if len(crypted_private_key) < 2476 or len(crypted_private_key) > 4780: # 2048 - 4096
            return False, {"status_code": 400, "error": "Parameter 'crypted_private_key' is to " + ("short" if len(crypted_private_key) < 2476 else "long") + "."}
        return True, None
    
    @staticmethod
    def two_factor_token(two_factor_token: Optional[str] = None) -> Tuple[bool, Optional[dict]]:
        """
        Validates a two_factor_token if it was specified, if it is 100 characters long and if it is hexadecimal.

        :param two_factor_token: The 2 factor token (Optional)
        """

        if two_factor_token is None:
            return False, {"status_code": 400, "error": "Parameter 'two_factor_token' is None."}
        if len(two_factor_token) != 100:
            return False, {"status_code": 400, "error": "Parameter 'two_factor_token' is to " + ("short" if len(two_factor_token) < 100 else "long") + "."}
        if re.match(r"^[0-9A-Fa-f]+$", two_factor_token):
            return False, {"status_code": 400, "error": "Parameter 'two_factor_token' is not hexadecimal."}
        return True, None


class SilentUndefined(Undefined):
    "Class to not get an error when specifying a non-existent argument"

    def _fail_with_undefined_error(self, *args, **kwargs):
        return None


class WebPage:
    "Class with useful tools for WebPages"

    @staticmethod
    def _minimize_tag_content(html: str, tag: str) -> str:
        """
        Minimizes the content of a given tag
        
        :param html: The HTML page where the tag should be minimized
        :param tag: The HTML tag e.g. "script" or "style"
        """

        tag_pattern = rf'<{tag}\b[^>]*>(.*?)<\/{tag}>'
        
        def minimize_tag_content(match: re.Match):
            content = match.group(1)
            content = re.sub(r'\s+', ' ', content)
            return f'<{tag}>{content}</{tag}>'

        return re.sub(tag_pattern, minimize_tag_content, html, flags=re.DOTALL | re.IGNORECASE)

    @staticmethod
    def minimize(html: str) -> str:
        """
        Minimizes an HTML page

        :param html: The content of the page as html
        """

        html = re.sub(r'<!--(.*?)-->', '', html, flags=re.DOTALL)
        html = re.sub(r'\s+', ' ', html)

        html = WebPage._minimize_tag_content(html, 'script')
        html = WebPage._minimize_tag_content(html, 'style')
        return html
    
    @staticmethod
    def render_template(file_path: Optional[str] = None, html: Optional[str] = None, **args) -> str:
        """
        Function to render a HTML template (= insert arguments / translation / minimization)

        :param file_path: From which file HTML code should be loaded (Optional)
        :param html: The content of the page as html (Optional)
        :param args: Arguments to be inserted into the WebPage with Jinja2
        """

        if file_path is None and html is None:
            raise ValueError("Arguments 'file_path' and 'html' are None")
        
        if not file_path is None:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File `{file_path}` does not exist")
        
        env = Environment(
            autoescape=select_autoescape(['html', 'xml']),
            undefined=SilentUndefined
        )

        if html is None:
            with open(file_path, "r") as file:
                html = file.read()
        
        template = env.from_string(html)

        html = template.render(**args)
        html = WebPage.minimize(html)

        return html


class Captcha:
    "Class to generate and verify a captcha"

    def __init__(self, captcha_secret: str, data: dict):
        """
        :param captcha_secret: A secret token that only the server knows to verify the captcha
        """

        self.captcha_secret = captcha_secret
        self.data = data
    
    def generate(self) -> Tuple[str, str]:
        "Generate a captcha for the client"

        image_captcha_code = generate_random_string(secrets.choice([8,9,10,11,12]), with_punctuation=False).upper()

        minimized_data = json.dumps(self.data, indent = None, separators = (',', ':'))
        captcha_prove = image_captcha_code + "//" + minimized_data

        crypted_captcha_prove = SymmetricEncryption(self.captcha_secret).encrypt(captcha_prove)

        image_captcha = ImageCaptcha(width=320, height=120, fonts=[
            os.path.join(NEEDED_DIR_PATH, "Comic_Sans_MS.ttf"),
            os.path.join(NEEDED_DIR_PATH, "DroidSansMono.ttf"),
            os.path.join(NEEDED_DIR_PATH, "Helvetica.ttf")
        ])

        captcha_image = image_captcha.generate(image_captcha_code)
        captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
        captcha_image_data = "data:image/png;base64," + captcha_image_data

        return captcha_image_data, crypted_captcha_prove
    
    def verify(self, client_input: str, crypted_captcha_prove: str) -> bool:
        """
        Verify a captcha

        :param client_input: The input from the client
        :param crypted_captcha_prove: The encrypted captcha prove generated by the generate function
        """

        captcha_prove = SymmetricEncryption(self.captcha_secret).decrypt(crypted_captcha_prove)

        captcha_code, data = captcha_prove.split("//")
        data = json.loads(data)

        return bool(not (data != self.data or captcha_code != client_input))