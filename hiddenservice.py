from sys import exit

if __name__ != "__main__":
    exit()

import os
import json
from tools import Tor, clear_console, get_system_architecture, VERSION
from rich.console import Console
from flask import Flask
import logging

SYSTEM, MACHINE = get_system_architecture()
TORRC_PATH = {"Windows": fr"C:\\Users\\{os.environ.get('USERNAME')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\Tor\\torrc", "Linux": "/etc/tor/torrc"}.get(SYSTEM, "/usr/local/etc/tor/torrc")

CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "data")

SERVICE_SETUP_CONF_PATH = os.path.join(DATA_DIR_PATH, "service-setup.conf")
DEFAULT_HIDDEN_SERVICE_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "hiddenservice")

console = Console()

if os.path.isfile(SERVICE_SETUP_CONF_PATH):
    with open(SERVICE_SETUP_CONF_PATH, "r") as readable_file:
        service_setup_info = json.load(readable_file)
else:
    service_setup_info = {}

if service_setup_info.get("restart_tor", True):
    if Tor.is_tor_daemon_alive():
        Tor.kill_tor_daemon()

HIDDEN_DIR = service_setup_info.get("hidden_service_dir", DEFAULT_HIDDEN_SERVICE_DIR_PATH)
HOSTNAME_PATH = os.path.join(HIDDEN_DIR, "hostname")
HIDDEN_PORT = service_setup_info.get("hidden_service_port", 8080)

with console.status("[bold green]Try to start the Tor Daemon with Service..."):
    Tor.start_tor_daemon(as_service=True)

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
        console.log(f"[red][Error]: Error while getting the hostname: '{e}', This error occurs when the Tor Hidden Service could not be started, below is a tutorial to fix this error:")

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

        with console.status("[bold green]Try to start the Tor Daemon with Service..."):
            Tor.start_tor_daemon(as_service=True)
        
        if os.path.isfile(HOSTNAME_PATH):
            break

    with open(HOSTNAME_PATH, "r") as readable_file:
        HOSTNAME = readable_file.read()

    clear_console()
else:
    console.print(f"[bright_blue]TOR Hidden Service:", HOSTNAME)

app = Flask("CipherChat")

log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

@app.route("/ping")
def ping():
    return "Pong! CipherChat Chat Service " + str(VERSION)

app.run(host = "localhost", port = HIDDEN_PORT)