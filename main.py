""" 
~-~-~-~
This is a copy of the free chat program "CipherChat" under GPL-3.0 license
GitHub: https://github.com/tn3w/CipherChat
~-~-~-~
"""

import os
import sys
import subprocess
from cons import CURRENT_DIR_PATH, DATA_DIR_PATH, TEMP_DIR_PATH, VERSION, BRIDGE_FILES, HTTP_PROXIES, HTTPS_PROXIES

if __name__ != "__main__":
    sys.exit(1)

REQUIREMENTS_PATH = os.path.join(CURRENT_DIR_PATH, "requirements.txt")
VENV_DIR_PATH = os.path.join(CURRENT_DIR_PATH, ".venv")
VENV_PYTHON_PATH = os.path.join(VENV_DIR_PATH, "bin", "python")

if os.path.isfile(REQUIREMENTS_PATH):
    with open(REQUIREMENTS_PATH, "r", encoding="utf-8") as f:
        requirements = [line.strip() for line in f if line.strip()]

    is_requirement_missing = False

    for requirement in requirements:
        if requirement == "pillow": requirement = "PIL"
        if requirement == "pysocks": requirement = "socks"
        try:
            __import__(requirement)
        except:
            is_requirement_missing = True
    
    if is_requirement_missing:
        this_python = sys.executable

        print("~ Automatic installation of all packages (this can take a few seconds) ... ")
        try:
            install_process = subprocess.Popen(
                [this_python, '-m', 'pip', 'install', '-r', REQUIREMENTS_PATH],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
            )
            stdout, stderr = install_process.communicate()
        except Exception as e:
            print(f"Error when automatically installing all requirements: {e}")

        if install_process.returncode != 0\
            and stderr is not None and not "--installed" in sys.argv:

            if "No module named pip" in stderr:
                print("\n[Error during automatic installation] Pip is not installed, use `sudo apt install python3-pip`")
                sys.exit()

            if "externally-managed-environment" in stderr:
                if os.path.isfile(VENV_PYTHON_PATH):
                    print(f"\nPlease use the following command to start:\n`{VENV_PYTHON_PATH} {os.path.join(CURRENT_DIR_PATH, 'main.py')} {' '.join(sys.argv)} --installed`")
                    sys.exit()

                if os.path.isdir(VENV_DIR_PATH):
                    os.rmdir(VENV_DIR_PATH)

                print("~ Installing a virtual environment ...")
                try:
                    install_process = subprocess.Popen(
                        [this_python, '-m', 'venv', VENV_DIR_PATH],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
                    )
                    install_process.wait()
                except Exception as e:
                    print(f"An error has occurred while creating the virtual environment: {e}")
                    sys.exit(2)
                
                print("~ Installing requirements again (this can take a few seconds) ... ")
                try:
                    install_process = subprocess.Popen(
                        [VENV_DIR_PATH, '-m', 'pip', 'install', '-r', REQUIREMENTS_PATH],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
                    )
                    install_process.wait()
                except Exception as e:
                    print(f"Error when automatically installing all requirements: {e}")

                print(f"\nPlease use the following command to start:\n`{VENV_PYTHON_PATH} {os.path.join(CURRENT_DIR_PATH, 'main.py')} {' '.join(sys.argv)} --installed`")
                sys.exit()

import tarfile
import json
import time
import re
from sys import argv as ARGUMENTS
import logging
from typing import Optional
from getpass import getpass
from rich.console import Console
from rich.style import Style
import hashlib
from flask import Flask, abort, request
from utils import clear_console, get_system_architecture, download_file, macos_get_installer_and_volume_path,\
                  get_password_strength, is_password_pwned, generate_random_string, show_image_in_console,\
                  Tor, Bridge, Linux, SecureDelete, AsymmetricEncryption, WebPage, BridgeDB, SymmetricEncryption, GnuPG,\
                  Proxy, load_persistent_storage_file, dump_persistent_storage_data, request_api_endpoint,\
                  shorten_text, load_request_data, return_error, PasswordAuthentication, Captcha, craft_response, AtExit

if "-v" in ARGUMENTS or "--version" in ARGUMENTS:
    print("CipherChat Version:", VERSION, "\n")
    sys.exit(0)

if "-a" in ARGUMENTS or "--about" in ARGUMENTS:
    clear_console()
    print(f"Current version: {VERSION}")
    print("CipherChat is used for secure chatting with end to end encryption and anonymous use of the Tor network for sending / receiving messages, it is released under the GPL v3 on Github. Setting up and using secure chat servers is made easy.")
    print("Use `python cipherchat.py -h` if you want to know all commands. To start use `python cipherchat.py`.")
    sys.exit(0)

CONSOLE = Console()
ORANGE_STYLE = Style(color="rgb(255,158,51)")

if "-k" in ARGUMENTS or "--killswitch" in ARGUMENTS:
    clear_console()
    start_time = time.time()

    with CONSOLE.status("[bold green]All files will be overwritten and deleted several times... (This can take several minutes)"):
        if os.path.isdir(DATA_DIR_PATH):
            SecureDelete.directory(DATA_DIR_PATH)

    end_time = time.time()

    CONSOLE.log("[green]Completed, all files are irrevocably deleted.","(took", end_time - start_time, "s)")
    time.sleep(5)

    os.system('cls' if os.name == 'nt' else 'clear')
    print("Good Bye. 💩")

    sys.exit(0)

if "-h" in ARGUMENTS or "--help" in ARGUMENTS:
    clear_console()
    print("> To start the client, simply do not use any arguments.")
    print("-h, --help                  Displays this help menu.")
    print("-a, --about                 Displays an About Cipherchat overview")
    print("-k, --killswitch            Immediately deletes all data in the data Dir and thus all persistent user data")
    print("-t, --torhiddenservice      Launches a CipherChat Tor Hidden Service")
    exit(0)

SYSTEM, MACHINE = get_system_architecture()

clear_console()

if SYSTEM not in ["Windows", "Linux", "macOS"]:
    CONSOLE.print(f"[red][Critical Error] Unfortunately, there is no version of CipherChat for your operating system `{SYSTEM}`.")
    sys.exit(2)

if not os.path.isdir(DATA_DIR_PATH):
    os.mkdir(DATA_DIR_PATH)

AtExit.delete_files()

GNUPG_EXECUTABLE_PATH = GnuPG.get_path()

if not os.path.isfile(GNUPG_EXECUTABLE_PATH):
    CONSOLE.print("[bold]~~~ Installing GnuPG ~~~", style=ORANGE_STYLE)
    if SYSTEM == "Linux":
        Linux.install_package("gpg")
    else:
        with CONSOLE.status("[green]Trying to get the download link for GnuPG (This may take some time)..."):
            while True:
                try:
                    download_link = GnuPG.get_download_link()
                except:
                    continue
                else:
                    break
        CONSOLE.print("[green]~ Trying to get the download link for GnuPG... Done")
        
        if download_link is None:
            CONSOLE.print("[red][Critical Error] GnuPG could not be installed because no download link could be found, install it manually.")
            sys.exit(2)

        if not os.path.isdir(TEMP_DIR_PATH):
            os.mkdir(TEMP_DIR_PATH)
        
        gnupg_file_path = download_file(download_link, TEMP_DIR_PATH, "GnuPG")

        if SYSTEM == "Windows":
            process = subprocess.Popen([gnupg_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        else:
            mount_command = ["hdiutil", "attach", gnupg_file_path]
            subprocess.run(mount_command)

            installer_path, volume_path = macos_get_installer_and_volume_path()
            
            process = subprocess.Popen(["open", installer_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        
        with CONSOLE.status("[green]GnuPG installation wizard started, waiting for completion..."):
            stdout, stderr = process.communicate()
            exit_code = process.returncode
        
        if SYSTEM == "macOS":
            unmount_command = ["hdiutil", "detach", volume_path]
            subprocess.run(unmount_command)

        if exit_code == 0:
            CONSOLE.print("[green]~ GnuPG has been installed")
        else:
            installation_url = {"Windows": "https://gnupg.org/download/#binary"}.get(SYSTEM, "https://gpgtools.org/")
            CONSOLE.print(f"[red][Critical Error] The GnuPG installation does not seem to have been successful. If errors occur, install GnuPG yourself at {installation_url}")
            CONSOLE.print(f"[red] Exit Code: `{exit_code}`; Standard output: `{stdout.decode('utf-8')}`; Error output: `{stderr.decode('utf-8')}`")
            sys.exit(2)
        
        with CONSOLE.status("[green]Cleaning up (this can take up to 2 minutes)..."):
            SecureDelete.directory(TEMP_DIR_PATH)
        CONSOLE.print("[green]~ Cleaning up... Done")
    GNUPG_EXECUTABLE_PATH = GnuPG.get_path()
    print()

TOR_EXECUTABLE_PATH = {
    "Windows": os.path.join(DATA_DIR_PATH, "tor/tor/tor.exe")
}.get(SYSTEM, os.path.join(DATA_DIR_PATH, "tor/tor/tor"))

if not os.path.isfile(TOR_EXECUTABLE_PATH):
    CONSOLE.print("[bold]~~~ Installing Tor ~~~", style=ORANGE_STYLE)
    with CONSOLE.status("[green]Trying to get the download links for Tor..."):
        while True:
            try:
                download_link, signature_link = Tor.get_download_link()
            except:
                continue
            else:
                break
    CONSOLE.print("[green]~ Trying to get the download links for Tor... Done")

    if None in [download_link, signature_link]:
        CONSOLE.print("[red][Critical Error] Tor Expert Bundle could not be installed because no download link or signature link could be found, install it manually.")
        sys.exit(2)

    if not os.path.isdir(TEMP_DIR_PATH):
        os.mkdir(TEMP_DIR_PATH)

    bundle_file_path = download_file(download_link, TEMP_DIR_PATH, "Tor Expert Bundle")
    bundle_signature_file_path = download_file(signature_link, TEMP_DIR_PATH, "Tor Expert Bundle Signature")

    skip_validating = False

    try:
        with CONSOLE.status("[green]Getting Proxy Session..."):
            os.environ['http_proxy'] = Proxy._select_random(HTTP_PROXIES)
            os.environ['https_proxy'] = Proxy._select_random(HTTPS_PROXIES)
        with CONSOLE.status("[green]Loading Tor Keys from keyserver.ubuntu.com..."):
            process = subprocess.Popen(
                [GNUPG_EXECUTABLE_PATH, "--keyserver", "keyserver.ubuntu.com", "--recv-keys", "0xEF6E286DDA85EA2A4BA7DE684E2C6E8793298290"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            process.wait()
    except subprocess.CalledProcessError as e:
        CONSOLE.log(f"[red]An Error occured: `{e}`")
        CONSOLE.print("[red][Critical Error] Could not load Tor Keys from keyserver.ubuntu.com")

        do_continue = input("\nContinue? [y - yes; n - no] ")
        if not do_continue.startswith("y"):
            sys.exit(2)
        
        skip_validating = True

    if not skip_validating:
        CONSOLE.print("[green]~ Loading Tor Keys from keyserver.ubuntu.com... Done")

        with CONSOLE.status("[green]Validating Signature..."):
            try:
                result = subprocess.run(
                    [GNUPG_EXECUTABLE_PATH, "--verify", bundle_signature_file_path, bundle_file_path],
                    capture_output=True, check=True, text=True
                )
                if not result.returncode == 0:
                    CONSOLE.log(f"[red]An Error occured: `{result.stderr}`")
                    CONSOLE.print("[red][Critical Error] Signature is invalid.")

                    do_continue = input("\nContinue? [y - yes; n - no] ")
                    if not do_continue.startswith("y"):
                        sys.exit(2)
                    skip_validating = True
            except subprocess.CalledProcessError as e:
                CONSOLE.log(f"[red]An Error occured: `{e}`")
                CONSOLE.print("[red][Critical Error] Signature verification failed.")

                do_continue = input("\nContinue? [y - yes; n - no] ")
                if not do_continue.startswith("y"):
                    sys.exit(2)
                skip_validating = True
        
        if not skip_validating:
            CONSOLE.print("[green]~ Validating Signature... Good Signature")

    with CONSOLE.status("[green]Extracting the TOR archive..."):
        ARCHIV_PATH = os.path.join(DATA_DIR_PATH, "tor")
        os.makedirs(os.path.join(DATA_DIR_PATH, "tor"), exist_ok=True)

        with tarfile.open(bundle_file_path, 'r:gz') as tar:
            tar.extractall(path=ARCHIV_PATH)

        if SYSTEM in ["macOS", "Linux"]:
            os.system(f"chmod +x {TOR_EXECUTABLE_PATH}")

    with CONSOLE.status("[green]Cleaning up (this can take up to 2 minutes)..."):
        SecureDelete.directory(TEMP_DIR_PATH)
    CONSOLE.print("[green]~ Cleaning up... Done")

if "-t" in ARGUMENTS or "--torhiddenservice" in ARGUMENTS:
    clear_console()
    CONSOLE.print("[bold]~~~ Starting Tor Hidden Service ~~~", style=ORANGE_STYLE)

    file_bytes = download_file("https://codeload.github.com/tn3w/CipherChat/zip/refs/heads/master",  operation_name = "Source Code", return_as_bytes = True)
    with CONSOLE.status("[green]Generating sha256 checksum..."):
        try:
            sha256_checksum = hashlib.sha256(file_bytes).hexdigest()
        except TypeError as e:
            CONSOLE.print(f"[red][Error] Error generating the sha265 checksum: `{e}`")
            sha256_checksum = ""
        else:
            CONSOLE.print("[green]~ Generating sha256 checksum... Done")

    with CONSOLE.status("[green]Loading Tor Configuration..."):
        control_port, socks_port = Tor.get_ports(9000)
        configuration = Tor.get_hidden_service_config()

        control_port = configuration.get("control_port", control_port)
        control_password = configuration.get("control_password")
        socks_port = configuration.get("socks_port", socks_port)
        hidden_service_dir = configuration["hidden_service_directory"]
        webservice_host, webservice_port = configuration["webservice_host"], configuration["webservice_port"]
        webservice_host = webservice_host.replace("localhost", "127.0.0.1")
        without_ui = configuration["without_ui"]
    CONSOLE.print("[green]~ Loading Tor Configuration... Done")

    tor_process, control_password = Tor.launch_tor_with_config(
        control_port, socks_port, [], True, control_password,
        {
            "hidden_service_dir": hidden_service_dir,
            "hidden_service_port": f"80 {webservice_host}:{webservice_port}"
        }
    )
    CONSOLE.print("[green]~ Starting Tor Executable.. Done")

    tor_atexit_id = AtExit.terminate_tor(control_port, control_password, tor_process)

    hostname_path = os.path.join(hidden_service_dir, "hostname")

    try:
        with open(hostname_path, "r", encoding = "utf-8") as readable_file:
            HOSTNAME = readable_file.read()
    except:
        HOSTNAME = "???"

    CONSOLE.print("\n[bright_blue]TOR Hidden Service:", HOSTNAME)

    ASYMMETRIC_ENCRYPTION = AsymmetricEncryption().generate_keys()
    PUBLIC_KEY, PRIVATE_KEY = ASYMMETRIC_ENCRYPTION.public_key, ASYMMETRIC_ENCRYPTION.private_key
    CAPTCHA_SECRET = generate_random_string(64)
    PWDAUTH_SECRET = generate_random_string(64)

    app = Flask("CipherChat")

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

    @app.route("/")
    def index():
        "Displays a user interface to the user when activated"

        if without_ui:
            return abort(404)

        return WebPage.render_template("index.html")
    
    @app.route("/about")
    def about():
        "Shows the user the 'About CipherChat' page that is intended to answer important questions"

        if without_ui:
            return abort(404)

        return WebPage.render_template("about.html", version = VERSION, status = "None")

    @app.route("/setup")
    @app.route("/setup/")
    @app.route("/setup/<operating_system>")
    def setup(operating_system: Optional[str] = None):
        "Shows the user an interface for installing CipherChat."

        if without_ui:
            return abort(404)

        return WebPage.render_template("setup.html", None, os = operating_system, hidden_service_hostname = HOSTNAME,
                                       sha256_checksum = sha256_checksum)
    
    @app.route("/ping")
    @app.route("/api/ping")
    def ping():
        "Used to check whether the server is online, which version it has and to get its public key"

        if not request.path.startswith("/api/"):
            if without_ui:
                return abort(404)
            
            return "🎾Pong! CipherChat Hidden Service; Version: " + VERSION

        return {"status": 200, "error": None, 
                "content": {"type": "CipherChat Hidden Service", "version": VERSION, "public_key": PUBLIC_KEY}}

    @app.route("/api/public_key")
    def api_public_key():
        "Returns the public key for encrypted communication with the server"

        return {"status": 200, "error": None, 
                "content": {"public_key": PUBLIC_KEY}}

    @app.route("/api/login")
    def api_login():
        "Route to request a password verification code and a captcha"

        data, error = load_request_data(ASYMMETRIC_ENCRYPTION)
        if not error is None:
            return return_error(error)

        username = data.get("username")
        if username is None:
            return return_error("The username parameter was not specified.")
        if len(username) < 4 or len(username) > 20 or bool(re.match(r'^[a-zA-Z0-9_]+$', username)):
            return return_error("The username is deformed.")

        user_passwordhash = "..." # Will be loaded here

        identification_data = {
            "username": username
        }

        pwdauth = PasswordAuthentication(PWDAUTH_SECRET, identification_data)
        crypted_verification_token, crypted_pwdauth_prove = pwdauth.server_generate_challenge(user_passwordhash)
        identification_data["pwdauth_prove"] = crypted_pwdauth_prove

        captcha_image_data, crypted_captcha_prove = Captcha(CAPTCHA_SECRET, identification_data).generate()

        response_data = {
            "crypted_verification_token": crypted_verification_token,
            "crypted_pwdauth_prove": crypted_pwdauth_prove,
            "captcha_image_data": captcha_image_data,
            "crypted_captcha_prove": crypted_captcha_prove
        }

        return craft_response(response_data, data["public_key"])

    @app.errorhandler(404)
    def not_found_errorhandler(_):
        "Handles the not found error"

        if request.path.startswith("/api/"):
            return {"status": 404, "error": "The requested endpoint does not exist or has been restricted.", "content": None}, 404

        if without_ui:
            return "", 404

        return WebPage.render_template("404.html"), 404
    
    @app.errorhandler(500)
    def internal_server_errorhandler(_):
        "Handles the internal server error"

        if request.path.startswith("/api/"):
            return {"status": 500, "error": "An error occurred when requesting the client, if you know the source of the error, report it on GitHub: https://github.com/tn3w/CipherChat/security", "content": None}, 500

        if without_ui:
            return "Shh, you found a bug? Report it on GitHub at https://github.com/tn3w/CipherChat/security", 500

        return WebPage.render_template("500.html"), 500

    app.run(host = webservice_host, port = webservice_port)

    sys.exit(0)

BRIDGE_CONFIG_PATH = os.path.join(DATA_DIR_PATH, "bridge.conf")
bridge_type, use_default_bridges, use_bridge_db = None, None, None

if os.path.isfile(BRIDGE_CONFIG_PATH):
    try:
        with open(BRIDGE_CONFIG_PATH, 'r', encoding='utf-8') as readable_file:
            file_config = readable_file.read()
        bridge_type, use_default_bridges, use_bridge_db = file_config.split("--")
        use_default_bridges = {"true": True, "false": False}.get(use_default_bridges, True)
        use_bridge_db = {"true": True, "false": False}.get(use_bridge_db, False)

        if not bridge_type in ["obfs4", "webtunnel", "snowflake", "meek_lite", "vanilla", "random"]:
            bridge_type = None

        if bridge_type in ["snowflake", "meek_lite"]:
            use_default_bridges = True
            use_bridge_db = False
    except Exception as e:
        CONSOLE.log(f"[red][Error] The following error occurs when opening and validating the bridge configurations: '{e}'")

if bridge_type is None:
    bridge_types = ["vanilla", "obfs4", "webtunnel", "snowflake (only buildin)", "meek_lite (only buildin)", "Random selection"]
    selected_option = 0

    while True:
        clear_console()
        CONSOLE.print("[bold]~~~ Bridge selection ~~~", style=ORANGE_STYLE)

        for i, option in enumerate(bridge_types):
            if i == selected_option:
                print(f"[>] {option}")
            else:
                print(f"[ ] {option}")

        key = input("\nChoose bridge type (c to confirm): ")

        if not key.lower() in ["c", "confirm"]:
            if len(bridge_types) < selected_option + 2:
                selected_option = 0
            else:
                selected_option += 1
        else:
            bridge_type = bridge_types[selected_option].replace(" (only buildin)", "").replace("Random selection", "random")
            break

    if bridge_type in ["snowflake", "meek_lite"]:
        use_default_bridges = True

if not isinstance(use_default_bridges, bool):
    use_buildin_input = input("Use buildin bridges? [y - yes, n - no]: ")
    use_default_bridges = use_buildin_input.startswith("y")

    if use_default_bridges:
        use_bridge_db = False

if not isinstance(use_bridge_db, bool):
    if bridge_type in ["vanilla", "obfs4", "webtunnel", "random"]:
        use_bridge_db_input = input("Use BridgeDB to get Bridges? [y - yes, n - no]: ")
        use_bridge_db = use_bridge_db_input.startswith("y")
    else:
        use_bridge_db = False

try:
    with open(BRIDGE_CONFIG_PATH, "w", encoding="utf-8") as writeable_file:
        writeable_file.write(
            '--'.join(
                [
                    bridge_type,
                    {True: "true", False: "false"}.get(use_default_bridges),
                    {True: "true", False: "false"}.get(use_bridge_db)
                ]
            )
        )
except Exception as e:
    CONSOLE.log(f"[red][Error] Error saving the bridge configuration file: '{e}'")

clear_console()

bridges = None

if not use_default_bridges:
    is_file_missing = False
    if bridge_type != "random":
        bridge_path = os.path.join(DATA_DIR_PATH, bridge_type + ".json")
        is_file_missing = not os.path.isfile(bridge_path)
    else:
        for specific_bridge_type in ["vanilla", "obfs4", "webtunnel"]:
            bridge_path = os.path.join(DATA_DIR_PATH, specific_bridge_type + ".json")
            is_file_missing = not os.path.isfile(bridge_path)

            if is_file_missing:
                break

    if is_file_missing:
        clear_console()
        CONSOLE.print("[bold]~~~ Downloading Tor Bridges ~~~", style=ORANGE_STYLE)

        bridges = Bridge.choose_buildin(bridge_type)
        control_port, socks_port = Tor.get_ports(4000)
        tor_process, control_password = Tor.launch_tor_with_config(control_port, socks_port, bridges)

        if tor_process is None:
            CONSOLE.print("[red][Error] Tor apparently could not be started properly")
        else:
            tor_atexit_id = AtExit.terminate_tor(control_port, control_password, tor_process)

            if not os.path.isdir(TEMP_DIR_PATH):
                os.mkdir(TEMP_DIR_PATH)

            session = Tor.get_requests_session(control_port, control_password, socks_port)

            if bridge_type != "random":
                if not use_bridge_db:
                    Bridge.download(bridge_type, session)
                else:
                    fail_counter = 0
                    while True:
                        if fail_counter > 5:
                            CONSOLE.print("\n[red][Critical Error] No connection to BridgeDB could be established, this may be due to the fact that Tor is not accessible")
                            input("Enter: ")
                            break

                        with CONSOLE.status("[green]Requesting Captcha from BridgeDB.."):
                            captcha_image_bytes, captcha_challenge_value = BridgeDB.get_captcha_challenge(bridge_type, session)

                        if None in [captcha_image_bytes, captcha_challenge_value]:
                            fail_counter += 1
                            time.sleep(1)
                            continue

                        while True:
                            print("-" * 20)
                            show_image_in_console(captcha_image_bytes)
                            captcha_input = input("Enter the characters from the captcha: ")

                            if captcha_input == "":
                                CONSOLE.print("\n[red][Critical Error] No captcha code was entered")
                                input("Enter: ")
                            elif len(captcha_input) < 5 or len(captcha_input) > 10:
                                CONSOLE.print("\n[red][Critical Error] The captcha code cannot be correct")
                                input("Enter: ")
                            else:
                                break

                        bridges = BridgeDB.get_bridges(bridge_type, captcha_input, captcha_challenge_value, session)

                        if bridges is None:
                            CONSOLE.print("\n[red][Critical Error] The captcha code was not correct")
                            input("Enter: ")
                        else:
                            break

                    with open(os.path.join(DATA_DIR_PATH, bridge_type + ".json"), "w", encoding = "utf-8") as writeable_file:
                        json.dump(bridges, writeable_file)
            else:
                if not use_bridge_db:
                    for specific_bridge_type in ["vanilla", "obfs4", "webtunnel"]:
                        bridge_path = os.path.join(DATA_DIR_PATH, specific_bridge_type + ".json")
                        Bridge.download(specific_bridge_type, session)
                else:
                    fail_counter = 0
                    while True:
                        if fail_counter > 5:
                            CONSOLE.print("\n[red][Critical Error] No connection to BridgeDB could be established, this may be due to the fact that Tor is not accessible")
                            input("Enter: ")
                            break

                        with CONSOLE.status("[green]Requesting Captcha from BridgeDB.."):
                            captcha_image_bytes, captcha_challenge_value = BridgeDB.get_captcha_challenge({"random": ""}.get(bridge_type, bridge_type), session)
        	            
                        if None in [captcha_image_bytes, captcha_challenge_value]:
                            fail_counter += 1
                            time.sleep(1)
                            continue

                        captcha_input = None
                        
                        while True:
                            print("-" * 20)
                            try:
                                show_image_in_console(captcha_image_bytes)
                            except:
                                break
                            captcha_input = input("Enter the characters from the captcha: ")

                            if captcha_input == "":
                                CONSOLE.print("\n[red][Critical Error] No captcha code was entered")
                                input("Enter: ")
                            elif len(captcha_input) < 5 or len(captcha_input) > 10:
                                CONSOLE.print("\n[red][Critical Error] The captcha code cannot be correct")
                                input("Enter: ")
                            else:
                                break
                        
                        if captcha_input == None:
                            continue

                        for specific_bridge_type in ["vanilla", "obfs4", "webtunnel"]:
                            bridge_path = os.path.join(DATA_DIR_PATH, specific_bridge_type + ".json")
                            if not os.path.isfile(bridge_path):
                                bridges = BridgeDB.get_bridges(specific_bridge_type, captcha_input, captcha_challenge_value, session)

                                if bridges is None:
                                    CONSOLE.print("\n[red][Critical Error] The captcha code was not correct")
                                    input("Enter: ")
                                    break

                                with open(os.path.join(DATA_DIR_PATH, specific_bridge_type + ".json"), "w", encoding = "utf-8") as writeable_file:
                                    json.dump(bridges, writeable_file)
                        
                        is_file_missing = False
                        for file in BRIDGE_FILES:
                            if not os.path.isfile(file):
                                is_file_missing = True
                        
                        if not is_file_missing:
                            break

            AtExit.remove_atexit(tor_atexit_id)
            with CONSOLE.status("[green]Terminating Tor..."):
                Tor.send_shutdown_signal(control_port, control_password)
                time.sleep(1)
                tor_process.terminate()

            with CONSOLE.status("[green]Cleaning up (this can take up to 1 minute)..."):
                SecureDelete.directory(TEMP_DIR_PATH)
            CONSOLE.print("[green]~ Cleaning up... Done")


PERSISTENT_STORAGE_CONF_PATH = os.path.join(DATA_DIR_PATH, "persistent-storage.conf")
PERSISTENT_STORAGE_KEYFILE_PATH = os.path.join(DATA_DIR_PATH, "persistent-storage.key")
use_persistant_storage, store_user_data = None, None
persistent_storage_password = None
persistent_storage_key = None

if os.path.isfile(PERSISTENT_STORAGE_CONF_PATH):
    try:
        with open(PERSISTENT_STORAGE_CONF_PATH, "r", encoding = "utf-8") as readable_file:
            persistent_storage_configuration = readable_file.read()

        try:
            conf_use_persistent_storage, conf_store_user_data, encrypted_persistent_storage_key = persistent_storage_configuration.split("--")
        except:
            conf_use_persistent_storage, conf_store_user_data = persistent_storage_configuration.split("--")
        use_persistant_storage = {"true": True, "false": False}.get(conf_use_persistent_storage)
        store_user_data = {"true": True, "false": False}.get(conf_store_user_data)

        if not use_persistant_storage:
            store_user_data = False

        while persistent_storage_password is None and use_persistant_storage:
            clear_console()
            CONSOLE.print("[bold]~~~ Persistent Storage ~~~", style=ORANGE_STYLE)
            input_persistent_storage_password = getpass("Please enter your Persistent Storage password: ")

            if input_persistent_storage_password == "":
                CONSOLE.print("\n[red][Error] No password was entered.")
                input("Enter: ")
                continue
                
            try:
                persistent_storage_key = SymmetricEncryption(input_persistent_storage_password).decrypt(encrypted_persistent_storage_key)
                if len(persistent_storage_key) != 128:
                    persistent_storage_key = None
                    raise Exception()
            except:
                CONSOLE.print("\n[red][Error] The password entered is not the Persistent Storage password")
                input("Enter: ")
                continue
            else:
                persistent_storage_password = input_persistent_storage_password
    except:
        pass

if use_persistant_storage is None:
    clear_console()
    CONSOLE.print("[bold]~~~ Persistent Storage ~~~", style=ORANGE_STYLE)
    input_use_persistant_storage = input("Would you like to use Persistent Storage? [y - yes or n - no] ")
    use_persistant_storage = input_use_persistant_storage.lower().startswith("y")

    if use_persistant_storage:
        input_store_user_data = input("Do you want us to save usernames and passwords? [y - yes or n - no] ")
        store_user_data = input_store_user_data.lower().startswith("y")
    else:
        store_user_data = False

if use_persistant_storage:
    while persistent_storage_password is None:
        clear_console()
        CONSOLE.print("[bold]~~~ Persistent Storage ~~~", style=ORANGE_STYLE)
        print("Would you like to use Persistent Storage? [y - yes or n - no]", {True: "yes", False: "no"}.get(use_persistant_storage))
        print("Do you want us to save usernames and passwords? [y - yes or n - no]", {True: "yes", False: "no"}.get(store_user_data))

        input_persistent_storage_password = getpass("\nPlease enter a strong password: ")

        if input_persistent_storage_password == "":
            CONSOLE.print("\n[red][Critical Error] No password was entered.")
            input("Enter: ")
            continue

        with CONSOLE.status("[green]Calculating the password strength..."):
            password_strength = get_password_strength(input_persistent_storage_password)
            password_strength_color = "green" if password_strength > 95 else "yellow" if password_strength > 80 else "red"
        CONSOLE.print(f"[{password_strength_color}]Password Strength: {password_strength}% / 100%")

        if password_strength < 80:
            CONSOLE.print("\n[red][Error] Your password is not secure enough.")
            input_continue = input("Still use it? [y - yes or n - no] ")

            if not input_continue.lower().startswith("y"):
                continue

        with CONSOLE.status("[green]Checking your password for data leaks..."):
            is_password_safe = is_password_pwned(input_persistent_storage_password)

        if not is_password_safe:
            CONSOLE.print("\n[red][Error] Your password is included in data leaks.")
            input_continue = input("Still use it? [y - yes or n - no] ")

            if not input_continue.lower().startswith("y"):
                continue

        input_persistent_storage_password_check = getpass("\nPlease enter your password again: ")

        if not input_persistent_storage_password == input_persistent_storage_password_check:
            CONSOLE.print("[red][Critical Error] The passwords do not match.")
            input("Enter: ")
            continue

        persistent_storage_password = input_persistent_storage_password
    
    if persistent_storage_key is None:
        persistent_storage_key = generate_random_string(128)
    
    persistent_storage_encryptor = SymmetricEncryption(persistent_storage_password + persistent_storage_key)

with open(PERSISTENT_STORAGE_CONF_PATH, "w", encoding = "utf-8") as writeable_file:
    persistent_storage_configuration = [{True: "true", False: "false"}.get(use_persistant_storage), {True: "true", False: "false"}.get(store_user_data)]
    if not persistent_storage_password is None:
        encrypted_persistent_storage_key = SymmetricEncryption(persistent_storage_password).encrypt(persistent_storage_key)
        persistent_storage_configuration.append(encrypted_persistent_storage_key)

    writeable_file.write('--'.join(persistent_storage_configuration))

while True:
    saved_hidden_services = {}

    SAVED_HIDDEN_SERVICES_PATH = os.path.join(DATA_DIR_PATH, "saved-hidden-services.pst")

    if use_persistant_storage:
        if os.path.isfile(SAVED_HIDDEN_SERVICES_PATH):
            try:
                saved_hidden_services = load_persistent_storage_file(SAVED_HIDDEN_SERVICES_PATH, persistent_storage_encryptor)
            except:
                pass
            
    current_hidden_service = None
    console_content = None
    if not len(saved_hidden_services) == 0:
        all_options = list(saved_hidden_services.keys()) + ["Use other hidden service"]
        selected_option = 0

        while True:
            clear_console()
            CONSOLE.print("[bold]~~~ Hidden Service selection ~~~", style=ORANGE_STYLE)
            console_content = ""

            for i, option in enumerate(all_options):
                if i == selected_option:
                    console_content += f"[>] {option}\n"
                    print(f"[>] {option}")
                else:
                    console_content += f"[ ] {option}\n"
                    print(f"[ ] {option}")

            key = input("\nSelect Hidden Service (c to confirm): ")

            if not key.lower() in ["c", "confirm"]:
                if len(all_options) < selected_option + 2:
                    selected_option = 0
                else:
                    selected_option += 1
            else:
                if not selected_option + 1 == len(all_options):
                   current_hidden_service = all_options[selected_option]
                break
    
    if current_hidden_service is None:
        clear_console()
        CONSOLE.print("[bold]~~~ Hidden Service selection ~~~", style=ORANGE_STYLE)
        if not console_content is None:
            print(console_content)
            print("Select Hidden Service (c to confirm): c\n")

        bridges = Bridge.choose_bridges(use_default_bridges, bridge_type)
        control_port, socks_port = Tor.get_ports(7000)

        with CONSOLE.status("[green]Starting Tor Executable..."):
            tor_process, control_password = Tor.launch_tor_with_config(control_port, socks_port, bridges)

        if tor_process is None:
            CONSOLE.print("[red][Critical Error] Tor apparently could not be started properly")
        else:
            tor_atexit_id = AtExit.terminate_tor(control_port, control_password, tor_process)
            while True:
                clear_console()
                CONSOLE.print("[bold]~~~ Hidden Service selection ~~~", style=ORANGE_STYLE)
                if not console_content is None:
                    print(console_content)
                    print("Select Hidden Service (c to confirm): c\n")
                service_address = input("Enter the Hostname of the CipherChat chat server: ")
                service_address = service_address.strip()

                if service_address == "":
                    CONSOLE.print("\n[red][Error] You have not entered a hidden service address.")
                    input("Enter: ")
                else:
                    if service_address == "b":
                        break
                    match = re.search(r"[a-z2-7]{56}\.onion", service_address)

                    if not match:
                        CONSOLE.print("\n[red][Error] You have not given a valid hidden service address")
                        input("Enter: ")
                    else:
                        with CONSOLE.status("[green]Getting Tor Session..."):
                            session = Tor.get_requests_session(control_port, control_password, socks_port)
                        
                        response_content = request_api_endpoint(service_address, "/api/ping", session = session)

                        if not response_content is None:
                            service_version = response_content.get("version")
                            if response_content.get("type") != "CipherChat Hidden Service":
                                CONSOLE.print(f"\n[red][Error] This service does not appear to be a CipherChat Hidden Service.")
                                input("Enter: ")
                            elif service_version != VERSION:
                                if isinstance(service_version, str) or isinstance(service_version, int):
                                    service_version = shorten_text(str(service_version), 6)
                                else:
                                    service_version = "None"

                                CONSOLE.print("\n[red][Error] This service does not have the same version as you" +
                                        f"\nService Version: {service_version}\nYour Version: {VERSION}")
                                input("Enter: ")
                            else:
                                current_hidden_service = service_address
                                break

            AtExit.remove_atexit(tor_atexit_id)
            with CONSOLE.status("[green]Terminating Tor..."):
                Tor.send_shutdown_signal(control_port, control_password)
                time.sleep(1)
                tor_process.terminate()
    
    if current_hidden_service is None:
        continue
    
    if use_persistant_storage:
        if os.path.isfile(SAVED_HIDDEN_SERVICES_PATH):
            try:
                saved_hidden_services = load_persistent_storage_file(SAVED_HIDDEN_SERVICES_PATH, persistent_storage_encryptor)
            except:
                pass
        else:
            saved_hidden_services = {}
        
        if saved_hidden_services.get(current_hidden_service) is None:
            saved_hidden_services[current_hidden_service] = {}
        
        try:
            dump_persistent_storage_data(SAVED_HIDDEN_SERVICES_PATH, saved_hidden_services, persistent_storage_encryptor)
        except:
            pass

    username = None

    saved_username = saved_hidden_services[current_hidden_service].get("username")
    if saved_username is not None:
        if not len(saved_username) < 4 and not len(saved_username) > 20 and not bool(re.match(r'^[a-zA-Z0-9_]+$', saved_username)):
            username = saved_username
    
    password = None

    saved_password = saved_hidden_services[current_hidden_service].get("password")
    if saved_password is not None:
        if not len(saved_password) < 8 and not get_password_strength(saved_password) < 70:
            password = saved_password

    if None not in [username, password]:
        bridges = Bridge.choose_bridges(use_default_bridges, bridge_type)
        control_port, socks_port = Tor.get_ports(7000)

        with CONSOLE.status("[green]Starting Tor Executable..."):
            tor_process, control_password = Tor.launch_tor_with_config(control_port, socks_port, bridges)

        tor_atexit_id = AtExit.terminate_tor(control_port, control_password, tor_process)
            
        request_api_endpoint(service_address, "/api/login") # Encrypted Request - Need Hidden Service Publ Key