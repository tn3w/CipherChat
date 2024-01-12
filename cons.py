""" 
~-~-~-~
This is a copy of the free chat program "CipherChat" under GPL-3.0 license
GitHub: https://github.com/tn3w/CipherChat
~-~-~-~
"""

import os

VERSION = 1.29

CURRENT_DIR_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "data")
TEMP_DIR_PATH = os.path.join(CURRENT_DIR_PATH, "tmp")

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

HTTP_PROXIES = ["154.236.168.179:1976", "103.153.246.65:3125", "195.93.172.32:3128", "82.97.215.240:80", "185.74.6.247:8080", "185.252.232.242:63475", "202.74.240.78:5020", "67.43.228.253:31951", "217.69.195.134:38080", "36.64.132.91:3127", "103.228.36.246:8888", "103.106.116.253:3123", "180.183.122.69:8080", "102.132.38.24:8080", "51.15.242.202:8888", "136.244.99.51:8888", "171.244.10.75:1911", "103.190.120.128:3128", "163.53.75.202:8080", "181.78.105.156:999", "103.118.47.252:8080", "103.229.52.152:8888", "67.43.227.227:3407", "203.174.15.84:8080", "212.108.145.195:9090", "176.98.33.103:8800", "138.204.20.160:8080", "39.62.10.187:8082", "93.157.248.108:88", "103.133.26.59:8181", "103.48.68.102:84", "47.89.184.18:3128", "103.166.253.57:84", "118.179.101.57:5020", "31.156.152.46:80", "177.12.118.160:80", "72.10.160.90:25473", "37.77.134.146:8080", "103.186.254.218:2016", "102.132.48.16:8080", "103.161.181.69:3128", "20.204.43.57:80", "123.126.158.50:80", "203.95.198.52:8080", "202.57.25.94:3127", "103.148.77.156:10248", "77.78.210.218:8080", "38.7.18.98:999", "185.217.143.96:80", "103.252.92.136:8888", "118.179.121.114:5020", "72.10.160.90:22491", "67.43.228.253:15961", "195.246.54.30:8080", "158.247.222.48:63128", "41.65.236.48:1976", "193.138.178.6:8282", "77.72.137.244:8076", "117.160.250.131:8899", "72.10.164.178:12767", "202.152.142.186:8080", "173.212.213.133:3128", "45.177.178.33:999", "154.236.179.227:1974", "74.192.74.37:8080", "45.7.64.81:999", "103.118.46.174:8080", "72.10.164.178:20739", "203.150.113.200:8080", "202.12.80.158:84", "103.105.125.94:84", "67.43.227.227:29787", "72.10.164.178:21251", "103.76.12.42:8181", "67.43.236.20:4287", "43.155.17.206:1020", "148.230.206.229:8080", "103.179.138.31:8080", "75.108.126.163:8089", "45.225.185.63:999", "103.115.29.65:8080", "110.12.211.140:80", "66.225.254.16:80", "115.127.91.107:8080", "103.162.205.251:8181", "103.13.120.116:3128", "103.13.29.157:1997", "203.192.217.6:8080", "47.107.61.215:8000", "173.209.66.179:16099", "103.39.49.156:3128", "45.188.164.48:1994", "205.196.184.69:50704", "159.138.122.91:18081", "36.92.93.21:8080", "8.213.151.128:3128", "83.146.94.125:38080", "103.228.246.250:7777", "178.115.243.26:8080", "116.203.28.43:80", "173.209.66.178:16099", "185.239.145.96:8530", "103.239.67.34:3128", "94.45.74.60:8080", "67.43.228.253:20983", "8.219.97.248:80", "103.118.46.176:8080", "207.248.108.129:20185", "185.229.111.183:45020", "103.228.37.48:8888", "67.43.236.20:1247", "72.10.164.178:14039", "203.19.38.114:1080", "181.78.65.218:999", "188.168.8.75:38080", "180.178.103.82:3131", "67.43.228.251:24817", "103.49.202.252:80", "72.10.164.178:31017", "64.56.150.102:3128", "114.129.2.82:8081", "208.67.28.28:58090", "64.183.86.211:8080", "64.225.4.17:10000", "203.95.198.112:8080", "159.65.77.168:8585", "51.178.220.185:3128", "47.91.104.88:3128", "91.230.154.149:38080", "103.152.112.145:80", "103.63.190.37:8080", "155.0.72.251:3128", "185.229.111.106:45020", "202.12.80.11:83", "209.121.164.50:31147", "38.52.221.146:999", "103.228.36.46:8888", "67.43.228.253:16631", "102.68.128.218:8080", "47.243.92.199:3128", "181.198.115.179:999", "118.172.239.231:8180", "102.212.86.57:8080", "90.74.184.32:999", "65.20.224.193:8080", "103.228.75.181:8888", "49.228.131.169:5000", "45.236.170.234:999", "101.255.150.178:3030", "103.25.195.114:3030", "103.110.89.243:8080", "79.137.199.255:1234", "135.125.102.121:3128", "91.92.155.207:3128", "45.162.82.244:8080", "177.230.144.185:10101", "103.235.34.114:8584", "1.0.171.213:8080", "36.88.111.250:8787", "5.9.153.179:63692", "162.248.224.103:80", "103.67.196.218:8888", "121.101.131.142:8080", "41.60.26.210:32650", "162.248.225.230:80", "122.155.165.191:3128", "38.9.131.68:8080", "193.42.12.64:3128", "121.183.80.210:80", "103.161.96.229:8888", "196.251.222.154:8102", "139.0.6.10:8080", "102.132.54.246:8080", "103.182.112.11:5000", "67.79.51.210:16099", "103.228.244.211:8080", "156.200.116.73:1976", "60.246.162.21:80", "103.130.106.121:82", "103.178.231.121:8888", "110.43.84.217:80", "79.110.201.235:8081", "200.140.139.162:8080", "201.212.248.186:8080", "103.209.61.202:3128", "118.69.134.2:80", "45.71.184.142:999", "144.91.105.4:3128", "156.200.116.68:1981", "162.223.89.84:80", "193.111.11.12:3128", "68.188.93.171:8080", "171.97.16.103:8080", "65.21.233.179:3136", "72.10.164.178:10995", "202.83.102.83:8080", "165.154.186.232:80", "212.25.190.102:8888", "196.41.60.194:8080", "58.234.116.197:8197", "47.254.90.125:3128", "195.151.230.1:8080", "45.224.22.177:999", "196.251.131.46:8080", "46.47.197.210:3128", "62.240.40.194:1974", "103.178.194.245:2016", "80.14.47.254:3128", "205.164.84.250:8591", "201.71.2.115:999", "103.160.3.17:8888", "129.150.39.9:80", "103.151.239.163:8888", "180.232.171.210:8080", "45.189.116.6:999", "182.160.109.162:8080", "67.43.228.253:13897", "41.65.236.35:1976", "116.58.162.45:3128", "117.54.114.96:80", "23.162.200.9:3128", "103.118.46.177:8080", "67.43.236.20:28901", "5.188.232.115:3128", "8.209.255.13:3128", "196.20.125.145:8083", "189.240.60.164:9090", "72.10.164.178:25779", "1.224.3.122:3888", "104.248.156.122:8888", "103.163.51.254:80", "103.190.120.34:8888", "178.128.200.87:80", "103.105.76.249:8080", "103.178.230.205:3128", "89.185.29.2:80", "23.162.200.150:3128", "196.251.135.183:8080", "154.236.189.22:1976", "117.160.250.163:8081", "103.183.121.125:3128", "65.21.228.58:3136", "103.118.44.203:8080", "159.138.122.91:18080", "119.39.68.75:2323", "67.43.236.20:3235", "88.80.103.9:6888", "36.91.98.115:8181", "116.202.28.30:3128", "221.153.92.39:80", "212.19.10.34:38080", "182.106.220.252:9091", "65.20.235.40:8080", "65.20.189.144:8080", "167.99.36.48:3128", "5.95.66.74:3128", "67.43.227.227:7339", "103.228.74.16:8888", "128.199.244.96:1234", "202.74.243.230:5020", "41.65.236.56:1981", "150.129.5.227:8080", "103.216.50.143:8080", "41.128.148.77:1976", "195.201.246.166:5566", "178.214.80.28:1981", "72.10.164.178:2777", "154.223.182.139:3128", "85.62.218.250:3128", "41.65.0.198:1976", "114.115.190.220:3128", "37.111.52.46:8081", "61.133.66.69:9002", "103.176.25.166:8888", "213.135.64.78:3333", "194.61.232.68:8095", "93.180.221.205:8080", "103.191.155.62:8080", "128.140.63.121:37679", "38.41.0.60:11201", "61.175.214.2:9091", "23.162.200.153:3128", "103.151.52.234:8888", "46.35.9.110:80", "94.16.105.36:3128", "103.78.171.10:84", "213.230.64.29:8080", "35.199.90.225:8888", "210.211.113.39:80", "103.160.3.65:8888", "14.241.236.189:2512", "165.16.31.14:8080", "5.9.153.179:63172", "124.120.57.97:80", "201.91.82.155:3128", "157.100.63.69:999", "202.5.51.161:8080", "195.181.172.211:8081", "65.108.9.181:80", "190.181.27.198:6332", "200.25.254.193:54240", "110.78.146.49:3127", "103.216.51.35:8080", "103.151.52.156:8888", "67.43.227.227:20207", "46.101.115.59:80", "41.65.55.10:1981", "47.91.65.23:3128", "191.102.254.9:8083", "217.30.173.162:3128", "200.166.248.217:128", "67.43.227.227:32341", "163.228.160.18:3128", "47.243.177.210:8088", "188.234.147.54:8019", "103.178.231.49:3128", "103.231.240.83:8990", "23.162.200.40:3128", "102.132.50.5:8080", "103.207.1.82:8080", "117.160.250.130:8899", "202.40.179.30:5020", "120.197.40.219:9002", "45.4.85.210:999", "102.213.146.244:8080", "195.96.162.162:38080", "118.163.120.181:58837", "91.241.217.58:9090", "72.10.164.178:2931", "201.217.246.212:8080", "103.84.235.162:8789", "103.161.112.233:3128", "67.43.228.253:11523", "200.0.227.38:8080", "103.136.82.252:82", "183.89.184.175:8080", "194.182.163.117:3128", "125.26.165.245:8080", "185.118.153.110:8080", "177.87.250.66:999", "202.94.174.48:4377", "58.20.21.248:2323", "72.10.160.90:3565", "138.97.14.247:8080", "103.190.120.62:3128", "34.16.176.111:8888", "133.18.234.13:80", "80.194.38.106:3333", "103.126.219.37:8080", "103.105.228.168:8080", "118.193.39.206:3128", "103.84.56.83:8080", "45.171.108.253:999", "103.183.121.37:8888", "189.240.60.169:9090", "154.236.179.239:1974", "67.43.236.20:29681", "62.3.30.70:8080", "45.174.79.80:999", "168.90.15.165:999", "103.177.35.200:8888", "176.236.124.252:10001", "102.212.86.37:8080", "103.182.112.11:3128", "106.105.120.14:80", "91.231.120.222:44100", "190.217.7.80:999", "47.74.152.29:8888", "154.65.39.7:80", "140.227.204.70:3128", "67.73.184.178:8081", "181.48.155.78:8003", "196.20.125.149:8083", "67.43.227.227:6351", "58.253.210.122:8888", "189.240.60.168:9090", "60.214.128.150:9091", "103.118.46.61:8080", "189.240.60.163:9090", "45.174.87.18:999", "117.160.250.138:8899", "202.57.25.112:8080", "103.191.165.61:8080", "23.152.40.15:5050", "117.160.250.132:80", "186.148.181.65:999", "181.231.67.213:6900", "35.225.16.82:2387", "201.71.2.49:999", "72.10.164.178:12159", "43.231.64.102:3128", "103.116.82.135:8080", "43.250.107.223:80", "14.172.41.48:8080", "102.132.201.202:80", "203.142.74.115:8080", "154.0.157.139:8080", "45.164.13.246:999", "185.20.198.250:8080", "122.54.34.10:8282", "67.43.236.20:2965", "59.124.9.67:3128", "212.108.134.10:9090", "103.76.12.42:80", "103.115.20.52:8080", "185.229.111.129:45020", "104.236.195.60:10003", "103.155.54.26:83", "103.68.85.171:8888", "67.43.227.227:16303", "212.112.120.252:45555", "103.67.196.220:8888", "106.105.218.244:80", "103.172.144.46:8080", "213.184.153.66:8080", "202.5.46.116:5020", "170.83.242.249:999", "154.85.58.149:80", "47.88.62.42:80", "186.96.15.70:8080", "45.65.138.48:999", "85.208.117.214:20241", "190.94.212.222:999", "181.81.245.194:4128", "195.85.207.212:7895", "38.45.44.109:999", "112.109.16.51:8080", "195.151.230.3:8080", "84.39.112.144:3128", "67.43.227.227:12827", "185.134.233.153:38080", "5.75.171.241:3918", "51.158.169.52:29976", "204.157.241.253:999", "103.172.23.101:8080", "72.10.160.90:16155", "20.219.137.240:3000", "42.96.0.14:3128", "103.48.71.102:83", "88.201.217.203:80", "119.110.67.238:57413", "222.113.173.133:10118", "72.10.164.178:28899", "202.142.158.114:8080", "172.93.213.177:80", "103.254.185.195:53281", "8.130.39.155:3389", "183.89.8.145:8080", "103.216.49.233:8080", "181.177.204.151:3128", "102.68.128.214:8080", "195.181.172.223:8081", "212.92.23.235:31288", "186.201.63.83:3128", "187.49.191.85:999", "67.43.227.227:28071", "150.107.136.110:8082", "159.203.178.50:3128", "217.26.67.57:3180", "91.230.65.107:38080", "181.78.19.249:999", "60.51.17.107:80", "122.3.41.154:8090", "142.93.72.28:10002", "194.247.173.17:8080", "187.73.225.96:777", "201.222.83.146:999", "196.251.222.210:8103", "103.239.66.184:3128", "114.156.77.107:8080", "72.10.164.178:2619", "72.10.164.178:31789", "87.247.251.240:3128", "87.255.10.60:8080", "103.161.118.213:3128", "103.161.97.24:8888", "103.178.232.252:8888", "217.24.245.58:8079", "140.227.201.157:32153", "45.71.81.73:9292", "103.188.252.65:1234", "47.100.254.82:80", "171.240.219.149:2017", "190.94.212.216:999", "185.191.236.162:3128", "138.2.81.47:2222", "188.235.0.207:8181", "179.12.51.141:41890", "67.43.228.253:27959", "65.108.84.93:8888", "103.48.69.113:82", "27.54.117.88:8089", "138.118.104.50:999", "177.130.104.106:33333", "38.156.233.74:999", "89.189.1.186:38080", "175.106.10.227:7878", "190.107.236.162:999", "216.137.184.253:80", "203.89.8.107:80", "189.240.60.171:9090", "103.228.36.148:8888", "182.160.107.1:5020", "188.132.222.3:8080", "58.234.116.197:80", "103.161.119.60:3128", "103.177.35.152:3128", "38.156.233.75:999", "132.248.159.223:3128", "103.190.121.155:3128", "186.96.96.163:999", "152.32.254.214:3128", "52.53.157.85:80", "103.83.232.122:80", "103.178.230.140:8888", "103.167.71.34:8080", "5.189.172.158:3128", "67.43.228.253:21227", "67.43.236.20:29389", "38.183.135.189:999", "102.132.48.198:8080", "43.156.0.125:8888", "41.65.103.9:1976", "67.43.227.227:21561", "182.160.106.117:5020", "181.191.94.126:8999", "67.43.236.20:8469", "13.81.217.201:80", "47.88.3.19:8080", "103.216.50.225:8080", "72.10.160.90:15513", "178.140.177.145:8889", "181.209.78.76:999", "187.73.102.70:9292", "190.103.177.131:80", "85.208.117.214:20436", "51.75.206.209:80", "103.118.44.21:8080", "119.159.246.197:3128", "103.26.109.62:84", "120.37.121.209:9091", "47.56.110.204:8989", "47.243.114.192:8180", "189.240.60.166:9090", "64.189.106.6:3129", "103.216.48.114:8080", "103.136.82.252:83", "58.11.158.134:8080", "185.49.30.169:8081", "103.48.71.102:84", "125.99.106.250:3128", "172.245.159.177:80", "204.157.247.218:999", "103.125.50.223:8080", "151.22.181.243:8080", "67.43.236.20:19175", "103.247.22.109:1111", "84.241.5.244:500", "181.78.105.151:999", "185.139.56.133:6961", "124.6.164.238:8080", "102.132.50.49:8080", "72.10.164.178:27011", "202.12.80.6:84", "46.149.77.234:80", "183.100.14.134:8000", "94.19.218.233:8193", "143.42.163.193:80", "85.208.117.214:20314", "62.113.103.192:80", "212.42.56.120:3128", "38.156.233.76:999", "62.240.40.82:1974", "131.196.8.33:999", "38.49.140.14:8080", "217.199.130.242:8080", "95.66.138.21:8880", "103.182.112.11:8000", "67.43.228.251:3649", "131.186.37.99:8080", "67.43.236.20:5817", "135.181.154.225:80", "23.162.200.179:3128", "176.98.33.107:8800"]


HTTPS_PROXIES = ["149.248.12.237:8888", "84.239.49.215:9002", "84.239.49.155:9002", "138.199.36.160:9002", "206.188.212.107:8443", "45.63.99.66:8888", "78.47.19.96:443", "193.176.84.39:9002", "172.105.197.49:8443", "205.178.136.163:8443", "84.239.49.40:9002", "138.199.35.206:9002", "205.178.137.253:8443", "62.133.46.7:9002", "198.16.76.29:443", "23.106.56.53:443", "165.225.113.216:8080", "138.201.152.216:443", "205.178.137.179:8443", "205.178.144.69:8443", "205.178.186.172:8443", "84.239.49.245:9002", "50.7.93.85:443", "205.178.186.14:8443", "198.16.70.27:443", "62.212.64.20:443", "51.89.216.202:3128", "165.225.72.154:11267", "206.188.212.183:8443", "198.16.78.43:443", "20.197.19.78:443", "181.16.201.58:8097", "84.239.49.234:9002", "84.239.49.51:9002", "138.2.151.139:443", "154.65.39.7:443", "138.199.35.210:9002", "152.67.198.149:1234", "146.190.177.143:443", "84.239.49.206:9002", "84.239.14.146:9002", "40.124.44.54:3129", "206.189.199.91:443", "198.16.76.69:443", "188.40.44.95:443", "217.12.21.249:443", "162.144.236.128:443", "104.129.194.43:11066", "134.209.108.22:8888", "206.188.204.17:8443", "193.176.84.34:9002", "205.178.144.80:8443", "156.146.59.20:9002", "5.161.97.210:8888", "205.178.136.34:8443", "23.106.56.13:443", "156.146.59.47:9002", "205.178.137.170:8443", "84.239.49.169:9002", "84.239.49.250:9002", "205.178.144.210:8443", "156.146.59.27:9002", "50.7.93.27:443", "206.188.209.178:8443", "38.47.238.145:3129", "84.239.14.174:9002", "147.75.92.248:8080", "156.146.59.16:9002", "198.16.74.204:443", "84.239.49.57:9002", "51.89.251.208:443", "41.173.24.38:443", "84.239.49.242:9002", "206.188.209.96:8443", "62.212.64.18:443", "138.199.35.218:9002", "200.19.177.120:443", "84.239.49.254:9002", "205.178.186.132:8443", "65.108.104.111:443", "23.108.96.79:443", "205.178.144.251:8443", "134.209.108.165:8888", "206.188.208.224:8443", "84.239.49.158:9002", "156.146.59.2:9002", "205.178.137.61:8443", "84.239.49.200:9002", "84.239.49.205:9002", "205.178.186.84:8443", "45.77.189.171:8888", "62.133.46.14:9002", "193.176.84.27:9002", "156.146.59.38:9002", "193.176.84.30:9002", "77.73.69.221:443", "156.146.59.36:9002", "207.178.166.187:443", "205.178.186.210:8443", "104.129.194.45:11066", "62.133.46.8:9002", "84.239.49.233:9002", "193.176.84.8:9002", "138.197.148.215:443", "205.178.137.11:8443", "197.249.5.150:8443", "138.199.35.215:9002", "51.15.135.81:443", "165.225.72.149:8080", "165.225.72.156:8080", "198.16.74.45:443", "134.209.144.177:443", "192.177.75.45:443", "206.188.212.161:8443", "206.188.206.44:8443", "141.148.41.219:443", "156.146.59.4:9002", "84.239.49.214:9002", "205.178.186.28:8443", "138.199.35.220:9002", "202.61.204.51:443", "205.178.137.101:8443", "84.239.49.224:9002", "5.161.90.87:8888", "51.158.233.238:8888", "198.16.74.43:443", "188.40.44.96:443", "205.178.186.56:8443", "84.239.49.226:9002", "84.239.49.198:9002", "193.15.14.198:443", "205.178.136.189:8443", "84.239.49.194:9002", "205.178.186.112:8443", "156.146.59.15:9002", "84.17.47.126:9002", "192.248.152.39:8888", "205.178.137.50:8443", "84.239.49.179:9002", "84.239.49.187:9002", "205.178.144.157:8443", "206.188.205.6:8443", "205.178.137.183:8443", "84.239.49.159:9002", "205.178.137.90:8443", "84.239.49.243:9002", "205.178.137.4:8443", "198.16.76.68:443", "84.239.49.231:9002", "104.129.205.15:8080", "193.176.84.10:9002", "5.161.117.167:8888", "209.126.6.159:443", "84.239.14.151:9002", "205.178.137.87:8443", "205.178.137.207:8443", "198.16.74.205:443", "162.246.248.214:443", "84.239.49.238:9002", "198.16.66.125:443", "199.168.148.131:11267", "84.239.49.37:9002", "205.178.144.208:8443", "84.239.49.38:9002", "198.16.66.141:443", "138.199.35.203:9002", "84.239.49.229:9002", "84.239.49.251:9002", "5.78.56.157:8888", "54.38.181.125:443", "206.188.212.251:8443", "193.176.84.23:9002", "80.66.64.64:443", "156.146.59.18:9002", "84.239.49.207:9002", "84.239.49.217:9002", "193.176.84.7:9002", "207.244.71.81:443", "84.239.49.171:9002", "84.17.47.150:9002", "34.120.193.19:443", "207.244.89.161:443", "84.239.49.178:9002", "205.178.137.100:8443", "205.178.137.119:8443", "205.178.186.88:8443", "23.106.56.37:443", "156.146.59.37:9002", "198.16.66.156:443", "146.59.233.62:3128", "156.146.59.19:9002", "93.91.80.6:443", "84.239.49.239:9002", "84.239.49.228:9002", "181.13.141.234:443", "206.188.212.80:8443", "217.182.170.224:443", "146.71.79.39:443", "84.239.49.193:9002", "109.107.189.214:443", "51.15.104.188:8888", "205.178.144.105:8443", "205.178.186.98:8443", "84.239.49.167:9002", "206.188.208.201:8443", "92.27.165.234:443", "193.176.84.26:9002", "5.78.56.144:8888", "205.178.137.230:8443", "84.239.14.149:9002", "5.161.120.159:8888", "162.240.76.92:443", "8.218.211.134:3128", "156.146.59.24:9002", "206.188.212.212:8443", "205.178.186.245:8443", "84.239.49.196:9002", "20.219.118.36:443", "23.106.56.22:443", "69.70.244.34:443", "84.239.49.54:9002", "84.239.49.213:9002", "156.146.59.11:9002", "206.188.206.141:8443", "104.129.194.38:11066", "138.199.35.199:9002", "62.133.46.16:9002", "223.19.111.185:443", "94.228.164.248:443", "84.239.49.235:9002", "62.133.46.15:9002", "206.188.212.229:8443", "23.106.56.38:443", "84.239.49.49:9002", "51.15.85.29:8888", "193.176.84.36:9002", "194.67.91.153:443", "194.140.198.23:443", "167.99.124.118:443", "134.122.26.11:443", "137.184.242.126:443", "206.188.212.162:8443", "206.188.208.235:8443", "94.242.57.245:443", "205.178.186.183:8443", "205.178.136.249:8443", "193.176.84.18:9002", "45.77.63.9:8888", "178.128.221.182:8888", "138.199.35.209:9002", "206.188.212.154:8443", "84.239.14.159:9002", "5.161.157.229:8888", "45.79.90.90:443", "206.188.206.162:8443", "58.220.95.68:8080", "84.239.49.201:9002", "128.199.12.243:3128", "103.179.190.121:443", "151.115.78.51:443", "205.178.186.247:8443", "205.178.136.211:8443", "84.239.49.157:9002", "82.157.35.125:443", "141.94.246.212:3128", "159.203.3.234:443", "205.178.136.242:8443", "205.178.137.198:8443", "84.239.14.160:9002", "205.178.186.52:8443", "162.240.75.37:443", "198.16.76.28:443", "205.178.137.212:8443", "84.239.49.156:9002", "156.146.59.41:9002", "46.101.115.59:443", "198.16.78.44:443", "84.239.49.50:9002", "84.239.49.53:9002", "193.176.84.12:9002", "205.178.186.104:8443", "205.178.137.76:8443", "84.239.49.61:9002", "50.7.142.182:443", "84.239.49.164:9002", "156.146.59.6:9002", "138.197.102.119:443", "23.106.249.35:443", "156.146.59.35:9002", "206.188.206.230:8443", "206.188.208.12:8443", "173.249.37.45:5050", "84.239.49.165:9002", "84.239.49.248:9002", "205.178.137.186:8443", "84.239.49.202:9002", "205.178.137.209:8443", "156.146.59.3:9002", "193.176.84.33:9002", "84.239.14.152:9002", "205.178.186.219:8443", "104.129.194.104:8080", "74.103.66.15:443", "84.239.49.227:9002", "84.239.49.62:9002", "206.188.204.66:8443", "84.239.49.210:9002", "77.73.68.159:443", "193.176.84.24:9002", "205.178.144.196:8443", "203.154.39.146:443", "206.188.212.64:8443", "78.28.152.111:443", "165.225.72.150:11066", "205.178.137.6:8443", "84.239.49.222:9002", "193.176.84.21:9002", "62.133.46.13:9002", "156.146.59.44:9002", "5.161.104.22:8888", "138.199.35.211:9002", "84.239.14.163:9002", "129.151.160.199:443", "205.178.144.141:8443", "162.144.233.16:443", "130.61.239.137:8443", "84.239.49.154:9002", "205.178.144.147:8443", "205.178.137.99:8443", "190.2.26.91:443", "5.78.56.143:8888", "205.178.136.90:8443", "206.188.212.235:8443", "84.239.14.157:9002", "141.147.9.254:443", "207.244.71.84:443", "23.106.56.12:443", "138.199.35.198:9002", "103.123.25.65:443", "84.239.49.223:9002", "84.239.14.158:9002", "198.16.66.140:443", "43.241.69.35:443", "23.106.248.251:443", "205.178.136.69:8443", "193.176.84.4:9002", "45.79.223.196:3129", "205.178.144.146:8443", "84.239.49.41:9002", "138.199.35.214:9002", "220.73.173.111:5000", "156.146.59.40:9002", "206.188.204.148:8443", "205.178.137.174:8443", "84.239.14.150:9002", "128.199.195.19:8888", "170.155.2.119:443", "34.122.187.196:443", "178.128.200.87:443", "205.178.136.159:8443", "23.106.56.36:443", "50.7.93.29:443", "41.204.63.118:443", "84.239.49.175:9002", "205.178.136.141:8443", "84.239.49.162:9002", "23.106.56.21:443", "5.161.64.85:8888", "23.106.56.19:443", "205.178.137.235:8443", "198.16.66.123:443", "193.176.84.3:9002", "84.17.47.122:9002", "137.220.53.16:8888", "62.133.46.4:9002", "147.182.132.21:443", "54.38.78.94:3128", "193.176.84.14:9002", "167.99.236.14:443", "206.188.212.168:8443", "202.60.194.23:443", "23.106.56.14:443", "138.199.35.217:9002", "50.7.142.180:443", "84.239.49.185:9002", "205.178.186.39:8443", "84.239.14.156:9002", "193.176.84.25:9002", "138.199.36.163:9002", "62.212.64.19:443", "205.178.186.2:8443", "198.16.66.139:443", "193.176.84.5:9002", "57.128.12.85:443", "165.225.72.38:11066", "193.176.84.31:9002", "198.16.66.101:443", "195.114.209.50:443", "206.188.212.132:8443", "84.239.49.45:9002", "84.239.49.208:9002", "37.9.171.157:443", "138.199.35.201:9002", "62.133.46.10:9002", "138.199.36.161:9002", "205.178.137.106:8443", "193.176.84.20:9002", "84.239.49.241:9002", "206.188.212.172:8443", "104.129.194.45:11267", "104.248.224.71:3129", "84.239.49.180:9002", "205.178.136.158:8443", "193.176.84.19:9002", "45.63.97.57:8888", "193.176.84.13:9002", "156.146.59.8:9002", "84.239.49.161:9002", "205.178.136.129:8443", "138.199.35.207:9002", "205.178.186.25:8443", "205.178.137.242:8443", "206.188.207.251:8443", "84.239.49.160:9002", "78.141.247.13:8888", "23.106.249.36:443", "205.178.136.221:8443", "193.176.84.29:9002", "206.188.209.109:8443", "84.239.49.211:9002", "205.178.186.11:8443", "205.178.186.27:8443", "156.146.59.33:9002", "45.32.146.61:8888", "206.188.205.85:8443", "51.91.109.83:443", "156.146.59.22:9002", "84.17.47.123:9002", "206.188.209.100:8443", "31.28.4.192:443", "205.178.144.114:8443", "84.239.49.39:9002", "205.178.136.68:8443", "84.239.49.220:9002", "193.176.84.40:9002", "144.91.90.109:443", "138.199.36.162:9002", "205.178.137.53:8443", "205.178.144.209:8443", "84.239.49.48:9002", "206.188.212.230:8443", "84.239.49.204:9002", "206.81.26.113:443", "84.239.49.176:9002", "199.168.148.131:11065", "104.129.194.105:11066", "157.245.97.60:443", "198.16.74.203:443", "154.57.7.36:443", "156.146.59.5:9002", "205.178.137.139:8443", "205.178.137.233:8443", "104.129.194.101:8080", "167.71.166.28:8443", "205.178.144.104:8443", "205.178.186.190:8443", "116.203.117.22:443", "199.168.148.131:8080", "193.176.84.22:9002", "205.178.137.173:8443", "206.188.212.220:8443", "45.92.108.112:443", "206.188.212.78:8443", "200.69.210.59:443", "192.53.114.26:443", "143.110.232.177:443", "193.176.84.16:9002", "104.129.194.44:11267", "5.161.45.24:8888", "103.37.111.253:10086", "205.178.137.228:8443", "104.129.194.46:11066", "138.199.42.123:443", "172.105.156.246:8443", "156.146.59.21:9002", "84.17.47.149:9002", "206.188.209.229:8443", "84.239.14.166:9002", "74.48.78.52:443", "34.125.38.1:443", "82.146.37.145:443", "138.199.35.216:9002", "122.176.48.148:443", "165.225.113.220:11066", "47.89.191.93:8088", "93.20.25.100:443", "206.188.209.191:8443", "78.28.152.113:443", "156.146.59.17:9002", "104.129.205.9:8080", "84.239.49.182:9002", "205.178.186.24:8443", "138.199.35.202:9002", "156.146.59.28:9002", "156.146.59.30:9002", "121.161.134.245:8888", "198.16.66.99:443", "62.133.46.11:9002", "205.178.144.97:8443", "84.239.49.197:9002", "84.239.49.184:9002", "155.138.151.230:8888", "54.39.207.190:443", "104.129.194.101:11267", "104.129.194.44:8080", "198.16.70.28:443", "84.239.49.170:9002", "205.178.136.16:8443", "205.178.186.58:8443", "162.210.194.37:443", "198.16.66.100:443", "62.133.46.3:9002", "62.133.46.6:9002", "144.217.46.29:443", "84.239.49.181:9002", "50.7.93.83:443", "51.210.216.54:443", "147.182.180.242:443", "84.17.47.125:9002", "142.93.61.46:443", "156.146.59.12:9002", "51.210.183.92:3128", "206.188.208.134:8443", "206.188.212.4:8443", "62.133.46.9:9002", "170.187.154.230:8443", "206.188.212.86:8443", "196.223.129.21:443", "206.188.205.5:8443", "193.176.84.6:9002", "205.178.137.181:8443", "35.171.245.156:443", "138.199.35.208:9002", "8.210.34.75:443", "162.223.116.54:443", "84.239.49.58:9002", "23.106.56.11:443", "13.81.217.201:443", "89.117.55.119:443", "138.199.35.219:9002", "84.239.49.253:9002", "135.125.237.78:3128", "205.178.186.103:8443", "184.168.123.21:443", "94.100.26.202:443", "201.217.49.2:443", "138.199.35.213:9002", "41.111.198.108:443", "217.12.23.236:443", "193.176.84.11:9002", "156.17.193.1:443", "45.32.134.61:8888", "198.16.76.27:443", "165.225.72.154:8080", "205.178.186.35:8443", "156.146.59.25:9002", "206.188.206.170:8443", "84.239.14.172:9002", "205.178.136.30:8443", "84.239.14.154:9002", "156.146.59.9:9002", "85.239.62.218:443", "84.239.49.219:9002", "45.114.142.178:443", "131.196.212.172:443", "84.239.49.252:9002", "138.199.35.212:9002", "165.225.72.156:11066", "156.146.59.32:9002", "23.106.249.34:443", "206.188.204.26:8443", "203.57.51.53:443", "84.239.49.232:9002", "84.239.14.169:9002", "205.178.186.41:8443", "205.178.186.46:8443", "154.65.39.8:443", "205.178.144.166:8443", "205.178.186.16:8443", "205.178.144.119:8443", "139.162.61.139:3128", "156.146.59.10:9002", "84.239.14.162:9002", "205.178.144.202:8443", "23.106.249.39:443", "155.138.144.61:8888", "205.178.186.42:8443", "205.178.136.80:8443", "206.188.212.238:8443", "50.7.93.84:443", "193.176.84.38:9002", "205.178.144.194:8443", "49.233.11.40:7777", "165.225.72.151:11267", "205.178.186.129:8443", "102.223.20.217:443", "143.244.182.101:443", "138.199.35.195:9002", "207.244.89.162:443", "84.239.49.209:9002", "152.67.210.180:1234", "84.239.49.192:9002", "84.239.49.172:9002", "198.16.66.157:443", "84.17.47.148:9002", "206.188.212.240:8443", "206.188.207.81:8443", "84.239.49.173:9002", "47.243.181.85:8083", "84.17.47.147:9002", "207.244.71.79:443", "50.7.93.28:443", "156.146.59.42:9002", "146.190.12.36:3128", "84.239.49.218:9002", "156.146.59.50:9002", "134.209.108.84:8888", "84.239.14.147:9002", "205.178.137.112:8443", "205.178.137.232:8443", "138.199.35.200:9002", "84.239.14.153:9002", "205.178.186.38:8443", "207.244.71.80:443", "27.254.162.101:443", "198.16.66.124:443", "155.138.159.63:8888", "84.239.49.203:9002", "156.146.59.49:9002", "205.178.137.84:8443", "205.178.136.101:8443", "84.239.14.171:9002", "71.235.183.92:443", "84.239.49.177:9002", "84.239.49.240:9002", "205.178.137.148:8443", "156.146.59.39:9002", "62.212.64.17:443", "193.176.84.9:9002", "206.188.208.159:8443", "103.37.111.253:10089", "5.189.154.210:443", "85.239.61.185:443", "198.16.66.155:443", "84.239.49.246:9002", "205.178.144.84:8443", "51.38.191.151:443", "1.234.23.159:443", "156.146.59.14:9002", "104.129.194.100:11267", "138.199.35.205:9002", "84.239.49.55:9002", "205.178.186.15:8443", "181.16.201.58:8091", "185.141.63.101:443", "23.94.143.167:443", "84.17.47.124:9002", "4.188.236.47:443", "23.106.56.51:443", "205.178.137.30:8443", "193.176.84.32:9002", "193.176.84.35:9002", "23.88.59.163:443", "205.178.136.118:8443", "205.178.136.151:8443", "205.178.137.82:8443", "205.178.186.62:8443", "84.239.49.163:9002", "205.178.136.28:8443", "199.168.148.131:11066", "212.46.38.104:443", "84.239.49.249:9002", "205.178.136.104:8443", "205.178.137.88:8443", "206.188.212.76:8443", "84.239.49.236:9002", "51.158.240.87:8888", "124.123.108.15:443", "167.99.174.59:443", "206.188.212.70:8443", "188.40.44.83:443", "206.188.209.146:8443", "138.199.35.196:9002", "84.239.49.189:9002", "102.69.236.152:443", "206.188.212.94:8443", "84.239.49.43:9002", "57.129.7.9:3128", "84.239.49.168:9002", "138.199.35.197:9002", "193.176.84.17:9002", "23.106.249.54:443", "205.178.186.18:8443", "138.199.35.204:9002", "142.11.222.22:443", "206.188.212.116:8443", "205.178.137.238:8443", "205.178.144.96:8443", "84.239.49.191:9002", "34.68.168.129:443", "196.1.95.124:443", "153.122.86.46:443", "156.146.59.34:9002", "205.178.136.209:8443", "205.178.144.165:8443", "84.239.14.175:9002", "206.188.212.163:8443", "193.176.84.37:9002", "84.239.49.212:9002", "84.239.49.230:9002", "84.239.49.42:9002", "197.243.20.178:443", "62.212.64.16:443", "84.239.49.247:9002", "84.239.14.164:9002", "205.178.144.212:8443", "156.146.59.23:9002", "68.183.143.134:443", "207.244.89.166:443", "206.188.212.249:8443", "150.230.250.166:1234", "84.239.14.167:9002", "190.5.77.211:443", "206.188.212.65:8443", "198.16.70.29:443", "84.239.49.166:9002", "84.239.49.47:9002", "84.239.49.46:9002", "156.146.59.43:9002", "205.178.136.45:8443", "205.178.137.185:8443", "35.203.65.254:443", "84.239.49.186:9002", "65.20.76.246:443", "165.225.62.134:8080", "205.178.144.218:8443", "205.178.136.74:8443", "206.188.209.4:8443", "84.239.49.56:9002", "84.239.49.190:9002", "156.146.59.45:9002", "84.239.14.176:9002", "167.172.96.213:443", "65.108.150.56:8443", "23.106.56.52:443", "84.239.49.225:9002", "84.239.49.188:9002", "156.146.59.46:9002", "84.239.14.148:9002", "80.154.6.2:8443", "57.128.196.169:3128", "104.129.194.103:11267", "5.78.52.164:8888", "206.188.209.179:8443", "62.133.46.12:9002", "84.239.49.244:9002", "84.239.14.170:9002", "143.198.240.30:443", "156.146.59.48:9002", "205.178.144.115:8443", "84.239.49.44:9002", "156.146.59.7:9002", "23.106.249.37:443", "141.148.63.29:443", "5.78.49.189:8888", "84.239.14.173:9002", "165.225.113.214:8080", "62.133.46.5:9002", "84.239.49.199:9002", "156.146.59.13:9002", "205.178.137.164:8443", "206.188.212.165:8443", "206.188.212.176:8443", "84.239.49.59:9002", "82.157.4.158:7777", "206.188.204.115:8443", "138.201.47.105:8443", "84.17.47.146:9002", "128.199.207.200:443", "205.178.137.151:8443", "5.9.112.103:443", "138.199.36.159:9002", "206.188.209.27:8443", "84.239.14.168:9002", "205.178.137.214:8443", "84.239.49.221:9002", "84.239.14.155:9002", "5.252.178.95:443", "51.178.18.88:443", "156.146.59.29:9002"]