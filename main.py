from sys import exit

if __name__ != "__main__":
    exit()

import os
from sys import argv as ARGUMENTS, executable as EXECUTABLE
from time import time
from rich.console import Console
import subprocess
import plistlib
from getpass import getpass
import secrets
import re
import json
from cons import VERSION, SYSTEM, CONSOLE, DATA_DIR_PATH, CURRENT_DIR_PATH, BRIDGES_CONF_PATH, NEEDED_DIR_PATH, TEMP_DIR_PATH, TOR_PATH, FACTS, TOR_EXT,\
    PERSISTENT_STORAGE_CONF_PATH, KEY_FILE_PATH_CONF_PATH, SERVICES_CONF_PATH, DEFAULT_BRIDGES_CONF
from utils import clear_console, is_password_save, get_password_strength, generate_random_string,\
    download_file, shorten_text, SecureDelete, Tor, GnuPG, Linux, SymmetricEncryption


if "-v" in ARGUMENTS or "--version" in ARGUMENTS:
    print("CipherChat Version", VERSION)
    exit()


if "-a" in ARGUMENTS or "--about" in ARGUMENTS:
    clear_console()
    print(f"Current version: {VERSION}")
    print("CipherChat is used for secure chatting with end to end encryption and anonymous use of the Tor network for sending / receiving messages, it is released under the GPL v3 on Github. Setting up and using secure chat servers is made easy.")
    print("Use `python cipherchat.py -h` if you want to know all commands. To start use `python cipherchat.py`.")
    exit(0)


if "-k" in ARGUMENTS or "--killswitch" in ARGUMENTS:
    clear_console()
    delete_path = {"n": DATA_DIR_PATH, "no": DATA_DIR_PATH}.get(input("Delete All? [y or n] ").lower(), CURRENT_DIR_PATH)

    start_time = time()

    with CONSOLE.status("[bold green]All files will be overwritten and deleted several times... (This can take several seconds)"):
        if os.path.isdir(delete_path):
            SecureDelete.directory(delete_path)

    end_time = time()

    CONSOLE.log("[green]Completed, all files are irrevocably deleted.","(took", end_time - start_time, "s)")
    exit(0)


if "-h" in ARGUMENTS or "--help" in ARGUMENTS:
    clear_console()
    print("> To start the client, simply do not use any arguments.")
    print("-h, --help                  Displays this help menu.")
    print("-a, --about                 Displays an About Cipherchat overview")
    print("-k, --killswitch            Immediately deletes all data in the data Dir and thus all persistent user data")
    print("-t, --torhiddenservice      Launches a CipherChat Tor Hidden Service")
    exit(0)


if not SYSTEM in ["Windows", "Linux", "macOS"]:
    clear_console()
    CONSOLE.print(f"[red][Error] Unfortunately, there is no version of CipherChat for your operating system `{SYSTEM}`.")
    exit()


clear_console()


# Choose what bridges to use
if os.path.isfile(BRIDGES_CONF_PATH):
    with open(BRIDGES_CONF_PATH, "r") as readable_file:
        bridges_configuration = readable_file.read().strip()
    
    try:
        bridge_conf = bridges_configuration.split("-")
        use_build_in, type_of_bridge = {"True": True}.get(bridge_conf[0], False), {"snowflake": "snowflake", "webtunnel": "webtunnel", "meek_lite": "meek_lite"}.get(bridge_conf[1], "obfs4")
    except:
        pass
else:
    while True:
        clear_console()

        print("\n~~~ Select TOR bridge type ~~~")
        print("obfs4:\nobfs4 (obfuscated bridges) is designed to obfuscate Tor traffic, making it harder to detect and block by disguising it as regular internet traffic.\nIts advantage lies in its effectiveness in bypassing censorship, but it can be resource-intensive, requiring more bandwidth. Additionally, it might be identified by advanced censorship systems.\n")
        print("snowflake:\nSnowflake is a pluggable transport for Tor that uses WebRTC technology to facilitate connections by enlisting volunteer proxies through web browsers to aid users in accessing the Tor network.\nThe advantage of Snowflake is its simplicity and decentralized nature; however, its dependency on volunteers and web browsers might result in sporadic availability and potential risks associated with relying on unknown proxies.\n")
        print("webtunnel:\nWebtunnel bridges use HTTP or HTTPS to bypass censorship by disguising Tor traffic within standard web traffic.\nThe advantage lies in its ability to blend Tor traffic with regular web traffic, making it difficult to differentiate. However, it might be vulnerable to sophisticated traffic analysis, and it might be blocked if the censoring system specifically targets its identifying patterns.\n")
        print("meek_lite:\n(Only Buildin)\nMeek_lite uses domain fronting to disguise Tor traffic as traffic to a major content delivery network (CDN) like Amazon or Microsoft, making it harder for censors to differentiate.\nIts advantage is in its high potential to bypass censorship, but it could be less efficient due to increased latency and reliance on a small number of front domains, which, if blocked, could disrupt the service. Additionally, it might attract attention due to its use of major CDN domains.\n")

        type_of_bridge = input("Choose Tor Bridge Type (obfs4, snowflake, webtunnel, meek_lite): ")
        if type_of_bridge in ["obfs4", "snowflake", "webtunnel", "meek_lite"]:
            break
        else:
            print(f"\n'{type_of_bridge}' is not a bridge type")
            input("Enter: ")
    
    use_build_in = {"y": True, "yes": True, "t": True, "true": True}.get(input("Do you want to use built-in bridges (recommended: no) [y or n]:  ").lower(), False)

    if not os.path.isdir(NEEDED_DIR_PATH):
        os.mkdir(NEEDED_DIR_PATH)
    
    save_content = str(use_build_in) + "-" + type_of_bridge
    with open(BRIDGES_CONF_PATH, "w") as writeable_file:
        writeable_file.write(save_content)
    
    if not use_build_in:
        Tor.download_bridges()
        with CONSOLE.status("Processing Bridges..."):
            Tor.process_bridges()
        with CONSOLE.status("[bold green]Cleaning up (This can take up to two minutes)..."):
            SecureDelete.directory(TEMP_DIR_PATH, quite = True)


# Install The Onion Router
if os.path.isfile(TOR_PATH):
    CONSOLE.log("[green]~ The Onion Router exists")
else:
    if SYSTEM == "Linux":
        with CONSOLE.status("[bold green]Try to install Tor via the Console..."):
            try:
                Linux.install_package("tor")
            except Exception as e:
                CONSOLE.log(f"[red]TOR could not be installed because of the following error: '{e}'")
                exit()
    elif SYSTEM in ["Windows", "macOS"]:
        print("Did you know?", secrets.choice(FACTS), "\n")
        with CONSOLE.status("[bold green]Trying to get the download links for Tor..."):
            download_link, signature_link = Tor.get_download_link()
        
        if download_link is None:
            raise Exception("[Error] Tor Browser could not be installed on your operating system, install it manually at https://www.torproject.org/download/ ")
        CONSOLE.log("[green]~ Downloaded Tor Links")
        
        if not os.path.isdir(TEMP_DIR_PATH):
            os.mkdir(TEMP_DIR_PATH)

        installation_file_path = os.path.join(TEMP_DIR_PATH, "torbrowser." + TOR_EXT)
        signature_file_path = os.path.join(TEMP_DIR_PATH, "signature.asc")

        download_file(download_link, installation_file_path, "Tor Browser")
        download_file(signature_link, signature_file_path, "Tor Browser Signature")

        with CONSOLE.status("[bold green]Trying to get the PGP Key Name for The Onion Router..."):
            key_name = GnuPG.search_key_name("Tor Browser Developers (signing key) <torbrowser@torproject.org>")
        CONSOLE.log("[green]~ Key Name received")
        
        gpg = GnuPG.load_public_keys(key_name)
        CONSOLE.log("[green]~ Public Keys Loaded")

        with CONSOLE.status("[bold green]Verify The Onion Router Installation File..."):
            with open(signature_file_path, 'rb') as signature_file:
                verification = gpg.verify_file(signature_file, installation_file_path)
        
        if verification.valid:
            CONSOLE.log("[green]~ The signature is valid")
        else:
            raise Exception("[Error] The signature does not seem to be valid, which may be due to The Onion Router installation file not being downloaded properly or torproject.org being infected.")

        with CONSOLE.status("[bold green]Installation file opened, waiting for the installation wizard to finish..."):
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
        CONSOLE.log("[green]The Hidden Router Installation Completed")

        with CONSOLE.status("[bold green]Cleaning up (This can take up to two minutes)..."):
            SecureDelete.directory(TEMP_DIR_PATH)


# Running Tor Hidden Service
if "-t" in ARGUMENTS or "--torhiddenservice" in ARGUMENTS:
    os.chdir(CURRENT_DIR_PATH)
    subprocess.run([EXECUTABLE, "hiddenservice.py"], check=True)
    exit()


# Use Persistent Storage?
if not os.path.isfile(PERSISTENT_STORAGE_CONF_PATH) and not os.path.isdir(DATA_DIR_PATH):
    while True:
        clear_console()
        print("(Please note that if Persistent Storage is not enabled, any messages or files retrieved will not be stored. The server deletes them after a single request, and no data is saved on the client side due to this setting.)")
        persistent_storage = input("Do you want to use encrypted persistent storage? [Y or n] ")

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
            master_password = getpass("Please enter a secure master password: ")

            password_strength = get_password_strength(master_password)
            print("Security Score:", password_strength, "/ 100%\n")

            is_save, error = is_password_save(master_password)
            if not is_save:
                print(error)
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

        with CONSOLE.status("[bold green]Encrypting the Key File path..."):
            crypted_key_file_path = SymmetricEncryption(master_password).encrypt(KEY_FILE_PATH)

        with CONSOLE.status("[bold green]Saving the Key File path..."):
            with open(KEY_FILE_PATH_CONF_PATH, "w", encoding="utf-8") as writeable_file:
                writeable_file.write(crypted_key_file_path)

    # Get Secret Key
    if not os.path.isfile(KEY_FILE_PATH):
        with CONSOLE.status("[bold green]Generate Secret Key..."):
            SECRET_KEY = generate_random_string(512)

        with CONSOLE.status("[bold green]Encrypt Secret Key with Password..."):
            crypted_secret_key = SymmetricEncryption(master_password).encrypt(SECRET_KEY)

        try:
            if not os.path.isdir(os.path.dirname(KEY_FILE_PATH)):
                os.mkdir(os.path.dirname(KEY_FILE_PATH))
        except:
            KEY_FILE_PATH = os.path.join(DATA_DIR_PATH, "keys.conf")

        with CONSOLE.status("[bold green]Saving the Secret Key..."):
            try:
                with open(KEY_FILE_PATH, "w", encoding="utf-8") as writeable_file:
                    writeable_file.write(crypted_secret_key)
            except:
                KEY_FILE_PATH = os.path.join(DATA_DIR_PATH, "keys.conf")
                with open(KEY_FILE_PATH, "w", encoding="utf-8") as writeable_file:
                    writeable_file.write(crypted_secret_key)
    else:
        with CONSOLE.status("[bold green]Loading the Encrypted Secret Key..."):
            with open(KEY_FILE_PATH, "r", encoding="utf-8") as readable_file:
                crypted_secret_key = readable_file.read()

        with CONSOLE.status("[bold green]Decrypting the Secret Key..."):
            SECRET_KEY = SymmetricEncryption( master_password).decrypt(crypted_secret_key)

    PASSKEY = master_password + SECRET_KEY


clear_console()


# Check and start The Onion Router Daemon
is_alive = False
with CONSOLE.status("[bold green]Getting whether Tor Daemon is alive..."):
    try:
        is_alive = Tor.is_tor_daemon_alive()
    except:
        pass

if not is_alive:
    with CONSOLE.status("[bold green]Try to start the Tor Daemon..."):
        Tor.start_tor_daemon()


# Getting the chat server
while True:
    clear_console()
    print("(Example: 4ryc2mpb67ciikwumutb47xgt7fxrnuek5xe62kx6dgdbemr6kbwxx47.onion)")
    service_address = input("Enter the URL of the CipherChat Tor Hidden Service: ")

    if not re.match(r"^[a-z2-7]{56}\.onion$", service_address):
        print("[Error] You have not given a valid Onion address")
        input("Enter: ")
    else:
        with CONSOLE.status("[bold green]Getting Tor Session..."):
            session = Tor.get_request_session()

        start_time = time()
        with CONSOLE.status("[bold green]Requesting Service Address..."):
            response = session.get("http://" + service_address + "/ping")
        end_time = time()

        CONSOLE.log("[green]Request took", end_time-start_time, "s")
        try:
            response.raise_for_status()
            response_content = response.content.decode("utf-8")
        except Exception as e:
            print(f"[Error] Error while requesting the ChatServer: '{e}'")
            input("Enter: ")
        else:
            shorten_response_content = shorten_text(response_content, 50)

            if not "Pong! CipherChat Chat Service " in response_content:
                print(f"[Error] This service does not appear to be a CipherChat server. Server Response: '{shorten_response_content}'")
                input("Enter: ")
            else:

                try:
                    SERVICE_VERSION = float(response_content.replace("Pong! CipherChat Chat Service ", ""))
                except Exception as e:
                    print(f"[Error] This service does not appear to be a CipherChat server. Server Response: '{shorten_response_content}'")
                    input("Enter: ")

                if SERVICE_VERSION != VERSION:
                    print("[Error] This service does not have the same version as you" +
                          f"\nService Version: {SERVICE_VERSION}\nYour Version: {VERSION}")
                    input("Enter: ")
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
        with CONSOLE.status("[bold green]Loading stored data for all services..."):
            with open(SERVICES_CONF_PATH, "r") as readable_file:
                crypted_services = readable_file.read()
        with CONSOLE.status("[bold green]Decrypting stored data for all services..."):
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


ACCOUNT_CREDS = None


# Login cycle
while not ACCOUNT_CREDS:
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
    
    header = {"login": "Log in", "register": "Register"}.get(service_action)
    
    while not SERVICE_ACCOUNT_NAME:
        clear_console()

        print(f"*** {header} ***")
        print(f"Connected to `{service_address}`\n")

        input_account_name = input("Please enter your account name: ")

        if len(input_account_name) > 20 or len(input_account_name) < 3:
            print("[Error] The account name has the wrong length, it must be longer than 3 characters and smaller than 20.")
            input("Enter: ")
        else:
            SERVICE_ACCOUNT_NAME = input_account_name

    while not SERVICE_ACCOUNT_PASSWORD:
        clear_console()

        print(f"*** {header} ***")
        print(f"Connected to `{service_address}`")
        print(f"Accountname is `{SERVICE_ACCOUNT_NAME}`\n")

        input_account_password = getpass("Please enter your account password: ")

        is_save, error = is_password_save(input_account_password)
        if not is_save:
            print(error)
            input("Enter: ")
        else:
            if service_action == "register":
                print("Password Score: ", get_password_strength(input_account_password), "/ 100%\n")

                input_account_password_repeat = getpass("Please enter your account password again: ")

                if input_account_password_repeat != input_account_password:
                    print("[Error] Passwords are not the same.")
                    input("Enter: ")
                else:
                    SERVICE_ACCOUNT_PASSWORD = input_account_password
                    break
            else:
                SERVICE_ACCOUNT_PASSWORD = input_account_password
                break

    if service_action == "login":
        # Authorization with password, then server sends private keys encrypted with password (if Persistent Storage is not enabled), and new encrypted messages
        pass
    else:
        # Solve captcha, send result and solution
        # Then: Generate key pair if persistent storage is off, send public key without encryption and private key with password encryption to server if not stored on device, also send password hash and account name
        pass
