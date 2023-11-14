import os
import platform
from typing import Tuple
import subprocess
from rich.console import Console

VERSION = 1.14

LOGO = '''
 dP""b8 88 88""Yb 88  88 888888 88""Yb  dP""b8 88  88    db    888888 
dP   `" 88 88__dP 88  88 88__   88__dP dP   `" 88  88   dPYb     88   
Yb      88 88"""  888888 88""   88"Yb  Yb      888888  dP__Yb    88   
 YboodP 88 88     88  88 888888 88  Yb  YboodP 88  88 dP""""Yb   88   

-~-    Programmed by TN3W - https://github.com/tn3w/CipherChat    -~-
'''

CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "data")
TEMP_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "tmp")
NEEDED_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "needed")

# Service Paths
SERVICE_SETUP_CONF_PATH = os.path.join(DATA_DIR_PATH, "service-setup.conf")
DEFAULT_HIDDEN_SERVICE_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "hiddenservice")
USERS_HIDDEN_SERVICE_PATH = os.path.join(DATA_DIR_PATH, "users-hiddenservice.json")

# Client Files
KEY_FILE_PATH_CONF_PATH = os.path.join(DATA_DIR_PATH, "keyfile-path.conf")
PERSISTENT_STORAGE_CONF_PATH = os.path.join(NEEDED_DIR_PATH, "persistent-storage.conf")
SERVICES_CONF_PATH = os.path.join(DATA_DIR_PATH, "services.conf")

# Bridges
BRIDGES_CONF_PATH = os.path.join(NEEDED_DIR_PATH, "bridges.conf")
DEFAULT_BRIDGES_CONF = False, "obfs4"
OBFS4_BUILDIN_BRIDGES = [
    "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=0",
    "obfs4 193.11.166.194:27015 2D82C2E354D531A68469ADF7F878FA6060C6BACA cert=4TLQPJrTSaDffMK7Nbao6LC7G9OW/NHkUwIdjLSS3KYf0Nv4/nQiiI8dY2TcsQx01NniOg iat-mode=0",
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
    "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
    "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
    "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1",
    "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    "obfs4 193.11.166.194:27020 86AC7B8D430DAC4117E9F42C9EAED18133863AAF cert=0LDeJH4JzMDtkJJrFphJCiPqKx7loozKN7VNfuukMGfHO0Z8OGdzHVkhVAOfo1mUdv9cMg iat-mode=0",
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "obfs4 85.31.186.26:443 91A6354697E6B02A386312F68D82CF86824D3606 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=0"
]
SNOWFLAKE_BUILDIN_BRIDGES = [
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=foursquare.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=foursquare.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn"
]
MEEKLITE_BUILDIN_BRIDGES = [
    "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
]
WEBTUNNEL_BUILDIN_BRIDGES = [
    "webtunnel [2001:db8:9443:367a:3276:1e74:91c3:7a5a]:443 54BF1146B161573185FBA0299B0DC3A8F7D08080 url=https://d3pyjtpvxs6z0u.cloudfront.net/Exei6xoh1aev8fiethee ver=0.0.1"
]
DOWNLOAD_BRIDGE_URLS = {
    "obfs4": {
        "github": "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4",
        "backup": "https://tor-bridges-collector.0xc0d3.xyz/Tor-Bridges-Collector-main/bridges-obfs4"
    },
    "snowflake": {
        "github": ["https://github.com/scriptzteam/Tor-Bridges-Collector/raw/main/bridges-snowflake-ipv4.rar", "https://github.com/scriptzteam/Tor-Bridges-Collector/raw/main/bridges-snowflake-ipv6.rar"],
        "backup": ["https://tor-bridges-collector.0xc0d3.xyz/Tor-Bridges-Collector-main/bridges-snowflake-ipv4.rar", "https://tor-bridges-collector.0xc0d3.xyz/Tor-Bridges-Collector-main/bridges-snowflake-ipv4.rar"]
    },
    "webtunnel": {
        "github": "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel",
        "backup": "https://tor-bridges-collector.0xc0d3.xyz/Tor-Bridges-Collector-main/bridges-webtunnel"
    }
}
IP_VERSIONS = ["ipv4", "ipv6"]


# Linux
DISTRO_TO_PACKAGE_MANAGER = {
    "ubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "debian": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "fedora": {"installation_command": "dnf install", "update_command": "dnf upgrade"},
    "centos": {"installation_command": "yum install", "update_command": "yum update"},
    "arch": {"installation_command": "pacman -S", "update_command": "pacman -Syu"},
    "opensuse": {"installation_command": "zypper install", "update_command": "zypper update"},
    "linuxmint": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "gentoo": {"installation_command": "emerge", "update_command": "emerge --sync"},
    "rhel": {"installation_command": "yum install", "update_command": "yum update"},
    "kali": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "tails": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "zorin": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "mx": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "solus": {"installation_command": "eopkg install", "update_command": "eopkg up"},
    "antergos": {"installation_command": "pacman -S", "update_command": "pacman -Syu"},
    "lubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "xubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
}
PACKAGE_MANAGERS = [
    {"version_command": "apt-get --version", "installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    {"version_command": "dnf --version", "installation_command": "dnf install", "update_command": "dnf upgrade"},
    {"version_command": "yum --version", "installation_command": "yum install", "update_command": "yum update"},
    {"version_command": "pacman --version", "installation_command": "pacman -S", "update_command": "pacman -Syu"},
    {"version_command": "zypper --version", "installation_command": "zypper install", "update_command": "zypper update"},
    {"version_command": "emerge --version", "installation_command": "emerge", "update_command": "emerge --sync"},
    {"version_command": "eopkg --version", "installation_command": "eopkg install", "update_command": "eopkg up"}
]

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

def get_gnupg_path() -> str:
    "Function to query the GnuPG path"

    gnupg_path = {"Windows": fr"C:\\Program Files (x86)\\GNU\\GnuPG\\gpg.exe", "macOS": "/usr/local/bin/gpg"}.get(SYSTEM, "/usr/bin/gpg")

    command = {"Windows": "where gpg"}.get(SYSTEM, "which gpg")

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        gnupg_path = result.strip()
    except:
        pass
    
    return gnupg_path

# GnuPG
KEYSERVER_URLS = ["hkp://keyserver.ubuntu.com:80", "keys.gnupg.net", "pool.sks-keyservers.net", "pgp.mit.edu"]
GNUPG_PATH = get_gnupg_path()

# Tor
TOR_PATH = {"Windows": fr"C:\\Users\\{os.environ.get('USERNAME')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe", "macOS": "/usr/local/bin/tor"}.get(SYSTEM, "/usr/bin/tor")
TORRC_PATH = {"Windows": fr"C:\\Users\\{os.environ.get('USERNAME')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\Tor\\torrc", "Linux": "/etc/tor/torrc"}.get(SYSTEM, "/usr/local/etc/tor/torrc")
TOR_EXT = {"Windows": "exe"}.get(SYSTEM, "dmg")
FACTS = ["Tor is a valuable tool for activists, journalists, and individuals in countries with restricted internet access, allowing them to communicate and access information without fear of surveillance.", "The Tor Browser was first created by the U.S. Naval Research Laboratory.", "The name 'Tor' originally stood for 'The Onion Router', referring to its multiple layers of encryption, much like the layers of an onion.", "The Tor Browser is open-source software, which means its source code is freely available for anyone to inspect, modify, and contribute to.", "Tor is designed to prioritize user privacy by routing internet traffic through a network of volunteer-operated servers, making it difficult to trace the origin and destination of data.",
         "The development of Tor has received funding from various government agencies, including the U.S. government, due to its importance in promoting online privacy and security.", "Tor allows websites to operate as hidden services, which are only accessible through the Tor network. This has led to the creation of websites that can't be easily traced or taken down.", "Websites on the Tor network often have addresses ending in '.onion' instead of the usual '.com' or '.org', adding to the uniqueness of the network.", "The strength of the Tor network lies in its thousands of volunteer-run relays worldwide. Users' data is passed through multiple relays, making it extremely difficult for anyone to trace their online activities."]

CONSOLE = Console()

GUTMANN_PATTERNS = [bytes([i % 256] * 100000) for i in range(35)]
DOD_PATTERNS = [bytes([0x00] * 100000), bytes([0xFF] * 100000), bytes([0x00] * 100000)]