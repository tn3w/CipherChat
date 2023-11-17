from sys import exit

if __name__ != "__main__":
    exit()

import os
from utils import Tor, clear_console, ArgumentValidator, JSON, Captcha, generate_random_string
from flask import Flask, request, render_template_string
import logging
import atexit
from cons import SYSTEM, TORRC_PATH, SERVICE_SETUP_CONF_PATH, DEFAULT_HIDDEN_SERVICE_DIR_PATH, VERSION, CONSOLE, TEMPLATES_DIR_PATH

service_setup_info = JSON.load(SERVICE_SETUP_CONF_PATH)

if service_setup_info.get("restart_tor", True):
    if Tor.is_tor_daemon_running():
        Tor.kill_tor_daemon()

HIDDEN_DIR = service_setup_info.get("hidden_service_dir", DEFAULT_HIDDEN_SERVICE_DIR_PATH)
HOSTNAME_PATH = os.path.join(HIDDEN_DIR, "hostname")
HIDDEN_PORT = service_setup_info.get("hidden_service_port", 8080)

with CONSOLE.status("[bold green]Try to start the Tor Daemon with Service..."):
    tor_process = Tor.start_tor_daemon(as_service=True)

atexit.register(Tor.at_exit_kill_tor, tor_process)

clear_console()

try:
    with open(HOSTNAME_PATH, "r") as readable_file:
        HOSTNAME = readable_file.read()
except Exception as e:
    hidden_dir, hidden_port = Tor.get_hidden_service_info()
    if not hidden_dir:
        hidden_dir = DEFAULT_HIDDEN_SERVICE_DIR_PATH
    while True:
        clear_console()
        CONSOLE.log(f"[red][Error]: Error while getting the hostname: '{e}', This error occurs when the Tor Hidden Service could not be started, below is a tutorial to fix this error:")

        print("\n~~~ Tutorial ~~~")
        if SYSTEM in ["Linux", "macOS"]:
            print("1. Open a new console where you run Command 2-4")
            print("2. Execute the command `sudo -s` to open a Sudo shell")
            print(fr"""3. Execute the following command: `echo -e "SocksPort 9050\nControlPort 9051\nHiddenServiceDir {hidden_dir}\nHiddenServicePort 80 127.0.0.1:{hidden_port}" | cat - {TORRC_PATH} > temp && mv temp {TORRC_PATH} && chmod 600 {TORRC_PATH}`""")
            print("4. Use 'systemctl restart tor.service' to restart Tor")
        else:
            print("""1. Press the Windows key and type `notepad.exe`, press "Open as admin". (This should open a text editor as administrator).""")
            print(f"""2. Now press "File > Open file" at the top and enter the following file: '{TORRC_PATH}' (This opens the correct file)""")
            print(f"""3. Now write the following phrases at the beginning of the file:""")
            print(f"SocksPort 9050\nControlPort 9051\nHiddenServiceDir {hidden_dir}\nHiddenServicePort 80 127.0.0.1:{hidden_port}")
            print("""4. Close the file by pressing "File > Save".""")
        input("Ready? Press Enter: ")

        with CONSOLE.status("[bold green]Try to start the Tor Daemon with Service..."):
            Tor.start_tor_daemon(as_service=True)
        
        if os.path.isfile(HOSTNAME_PATH):
            break

    with open(HOSTNAME_PATH, "r") as readable_file:
        HOSTNAME = readable_file.read()

    clear_console()

CONSOLE.print(f"[bright_blue]TOR Hidden Service:", HOSTNAME)

CAPTCHA_SECRET = generate_random_string(32)

app = Flask("CipherChat")

log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

@app.route("/ping")
def ping():
    return "Pong! CipherChat Chat Service " + str(VERSION)

@app.route("/safe_usage.txt")
def safe_usage():
    SAFE_USAGE_PATH = os.path.join(TEMPLATES_DIR_PATH, "safe_usage.txt")
    if not os.path.isfile(SAFE_USAGE_PATH):
        return "No safe_usage.txt provided."
    with open(SAFE_USAGE_PATH, "r") as readable_file:
        safe_usage = readable_file.read()

    new_safe_usage = ""
    for line in safe_usage.split("\n"):
        if not line.strip().startswith("#"):
            new_safe_usage += line + "\n"

    return render_template_string("<pre>{{ safe_usage }}</pre>", safe_usage=new_safe_usage)

@app.route("/api/register_captcha", methods = ["GET"])
def api_register_captcha():
    if not request.method == "POST":
        return {"status_code": 400, "error": "Invalid Request method"}
    if not request.is_json:
        return {"status_code": 400, "error": "No valid data given as json"}
    
    data = request.json
    if not isinstance(data, dict):
        return {"status_code": 400, "error": "Data is not given as a dictionary"}

    username = data.get("username")
    hashed_password = data.get("hashed_password")
    hashed_chat_password = data.get("hashed_chat_password")
    public_key = data.get("public_key")
    crypted_private_key = data.get("crypted_private_key")
    two_factor_token = data.get("two_factor_token")

    is_valid_username, username_error = ArgumentValidator.username(username)
    if not is_valid_username:
        return username_error
    
    is_valid_hashed_password, hashed_password_error = ArgumentValidator.hashed_password(hashed_password)
    if not is_valid_hashed_password:
        return hashed_password_error
    
    is_valid_hashed_chat_password, hashed_chat_password_error = ArgumentValidator.hashed_chat_password(hashed_chat_password)
    if not is_valid_hashed_chat_password:
        return hashed_chat_password_error
    
    is_valid_public_key, public_key_error = ArgumentValidator.public_key(public_key)
    if not is_valid_public_key:
        return public_key_error
    
    is_valid_crypted_private_key, crypted_private_key_error = ArgumentValidator.crypted_private_key(crypted_private_key)
    if not is_valid_crypted_private_key:
        return crypted_private_key_error
    
    is_valid_two_factor_token, two_factor_token_error = ArgumentValidator.two_factor_token(two_factor_token)
    if not is_valid_two_factor_token:
        return two_factor_token_error
    
    data = {
        "username": username,
        "hashed_password": hashed_password,
        "hashed_chat_password": hashed_chat_password,
        "public_key": public_key,
        "crypted_private_key": crypted_private_key,
        "two_factor_token": two_factor_token
    }

    captcha_image_data, crypted_captcha_prove = Captcha(CAPTCHA_SECRET).generate()
    
    return {
        "image_data": captcha_image_data,
        "captcha_prove": crypted_captcha_prove
    }

app.run(host = "localhost", port = HIDDEN_PORT)