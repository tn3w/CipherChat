""" 
~-~-~-~
This is a copy of the free chat program "CipherChat" under GPL-3.0 license
GitHub: https://github.com/tn3w/CipherChat
~-~-~-~
"""

import os

VERSION = 1.45

CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "data")
TEMP_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "tmp")
ASSETS_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "assets")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/119.0.2151.97",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edge/44.18363.8131",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
]

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

BRIDGE_FILES = [
    os.path.join(DATA_DIR_PATH, "obfs4.json"),
    os.path.join(DATA_DIR_PATH, "vanilla.json"),
    os.path.join(DATA_DIR_PATH, "webtunnel.json")
]

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

VANILLA_BUILDIN_BRIDGES = [
    "45.33.1.189:443 F9DFF618E7BA6C018245D417F39E970C2F019BAA",
    "217.160.8.91:9706 FEA00E8A631508D55012222B4D31B68B31791D35",
    "104.156.237.105:55292 F9F2B2D90FDF48394A00A1BE7E9D849C45B7845D",
    "141.5.100.255:16749 9FA6E82152189521B3C78ACCF41F8B9F5069D26C",
    "92.117.182.55:443 755BA0E7F4FE1A197EDF0D83681D2572AF39CB2E",
    "158.69.207.216:9001 6565F31D9EC0C7DFFEA1920BE3BA4C73EF35B5C4",
    "192.210.175.193:443 CE7870C73917FF91CA8DD068BBA8C771F85CAD19",
    "116.202.247.57:9001 E094CE3392E59129B44B01DB5C63AA52F5FF4566",
    "199.231.94.134:443 040FE18615AB10F10E6942B53C3CAAC5BF74736B",
    "217.182.196.65:443 8FD3BAF5E14EBE1124D6253D59882AFE1C2B9B8E",
]

SNOWFLAKE_BUILDIN_BRIDGES = [
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=foursquare.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=foursquare.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn"
]

WEBTUNNEL_BUILDIN_BRIDGES = [
    "webtunnel [2001:db8:9443:367a:3276:1e74:91c3:7a5a]:443 54BF1146B161573185FBA0299B0DC3A8F7D08080 url=https://d3pyjtpvxs6z0u.cloudfront.net/Exei6xoh1aev8fiethee ver=0.0.1",
    "webtunnel [2001:db8:3d87:58ab:4ec3:21ba:913f:99d8]:443 E4B91C347D685E929C1B7CE84CC27EB073127EA6 url=https://borntec.autos/poh8aiteaqu6oophaiXo ver=0.0.1",
    "webtunnel [2001:db8:f501:5e2b:27a0:2475:bf96:10d8]:443 B31170341D35C6E1FB5416BEB219E349D8FE093D url=https://files.gus.computer/kd2DLzS5EJEcB5LRsHS22pLE ver=0.0.1"
]

MEEKLITE_BUILDIN_BRIDGES = [
    "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
]

BRIDGE_DOWNLOAD_URLS = {
    "vanilla": {
        "github": "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-vanilla",
        "backup": "https://tor-bridges-collector.0xc0d3.xyz/Tor-Bridges-Collector-main/bridges-vanilla"
    },
    "obfs4": {
        "github": "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4",
        "backup": "https://tor-bridges-collector.0xc0d3.xyz/Tor-Bridges-Collector-main/bridges-obfs4"
    },
    "webtunnel": {
        "github": "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel",
        "backup": "https://tor-bridges-collector.0xc0d3.xyz/Tor-Bridges-Collector-main/bridges-webtunnel"
    }
}

DEFAULT_BRIDGES = {
    "vanilla": VANILLA_BUILDIN_BRIDGES,
    "obfs4": OBFS4_BUILDIN_BRIDGES,
    "snowflake": SNOWFLAKE_BUILDIN_BRIDGES,
    "webtunnel": WEBTUNNEL_BUILDIN_BRIDGES,
    "meek_lite": MEEKLITE_BUILDIN_BRIDGES
}

HTTP_PROXIES = ["71.19.249.97:8443","117.251.103.186:8080","115.239.234.43:7302","47.242.3.214:8081","201.174.175.82:999","35.185.254.159:80","47.100.207.117:8080","221.226.109.229:7302","103.147.182.36:80","104.199.219.13:3128","103.163.51.254:80","139.59.1.14:8080","220.67.2.2:80","122.175.58.131:80","134.209.29.120:3128","128.199.202.122:8080","167.71.5.83:3128","103.149.130.38:80","123.126.158.50:80","212.23.175.80:8443","201.182.251.140:999","103.157.219.4:80","116.130.233.22:3129","82.69.16.184:80","20.44.206.138:80","103.210.57.243:80","64.225.8.179:10000","185.200.119.90:8443","138.68.60.8:3128","64.225.8.115:9994","163.181.123.54:8080","159.203.61.169:3128","8.219.97.248:80","103.170.185.226:80","34.80.202.6:3128","203.85.120.69:8080","198.199.86.11:3128","16.163.88.228:80","35.189.183.169:3128","209.97.150.167:3128"]


HTTPS_PROXIES = ["71.19.249.97:8443","117.251.103.186:8080","201.174.175.82:999","35.194.228.247:3128","123.126.158.50:80","212.23.175.80:8443","116.130.233.22:3129","181.143.143.125:999","20.44.206.138:80","185.200.119.90:8443","64.225.8.115:9994","34.80.202.6:3128","64.225.4.85:9997"]