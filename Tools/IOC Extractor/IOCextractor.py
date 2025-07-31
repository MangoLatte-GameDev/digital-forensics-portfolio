import os
import re
import requests
import time
import ctypes
import sys
import json
import csv
import ipaddress
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

# === CONFIG ===
VIRUSTOTAL_API_KEY = ""
ABUSEIPDB_API_KEY = ""
SCAN_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\\AppData\\Local\\Logs"),
    r"C:\\Users",
    r"C:\\ProgramData",
    r"C:\\Windows\\System32\\LogFiles"
]
ALERT_FILE = "alerts.txt"
RESULT_FILE = "results.txt"
SCAN_DB_FILE = "scan_db.json"
IOC_DB_FILE = "ioc_db.json"

# === REGEX ===
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"


# Get folder where the script is located
BASE_DIR = Path(__file__).resolve().parent

json_path = BASE_DIR / "test_files" / "test.json"
txt_path = BASE_DIR / "test_files" / "test.txt"
csv_path = BASE_DIR / "test_files" / "test.csv"

# === Load/Save Databases ===
def load_jason_file(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {} if default is None else default
def save_jason_file(path, data):
    try:
        # create parent directories if they don't exist
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except (IOError, TypeError)as e:
        print(f"Error saving JSON file {path}: {str(e)}")
def load_txt_file(path, default=None):
     try:
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
     except FileNotFoundError:
        return [] if default is None else default
     except UnicodeDecodeError:
        print(f"Warning: Could not read {path} as UTF-8 text")
        return [] if default is None else default
def save_txt_file(path, data):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:
            if isinstance(data, str):
                f.write(data)
            else:
                f.write('\n'.join(str(item) for item in data))
            f.write('\n')  # Ensure trailing newline
    except IOError as e:
        print(f"Error saving text file {path}: {str(e)}")
def load_csv_file(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            return [row for row in reader if row]
    except FileNotFoundError:
        return [] if default is None else default
    except UnicodeDecodeError:
        print(f"Warning: Could not read {path} as UTF-8 CSV")
        return [] if default is None else default
def save_csv_file(path, data):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            for row in data:
                writer.writerow(row if isinstance(row, list) else [row])
    except IOError as e:
        print(f"Error saving CSV file {path}: {str(e)}")


# === IP Check ===
def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return True
    

# === VirusTotal API ===
def check_virustotal(ioc, ioc_type="ip"):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    if ioc_type=="ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "file":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        print(f"Unknown IOC type: {ioc_type}")
        return None
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"{Fore.YELLOW}[VT] Warning: {response.status_code} for {ioc}{Style.RESET_ALL}")
            return None
    except requests.RequestException as e:
        print(f"{Fore.RED}[VT] Error: {str(e)}{Style.RESET_ALL}")
        return None
        
# === AbuseIPDB API ===
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "30"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"{Fore.YELLOW}[ABUSEIPDB] Warning: {response.status_code} for {ip}{Style.RESET_ALL}")
            return None
    except requests.RequestException as e:
        print (f"{Fore.RED}[ABUSEIPDB] Error: {str(e)}{Style.RESET_ALL}")
        return None
    

def test_api_queries():
    test_ip = "8.8.8.8"  # or something more suspicious
    print(Fore.CYAN + f"[TEST] VirusTotal on {test_ip}:" + Style.RESET_ALL)
    vt_result = check_virustotal(test_ip, ioc_type="ip")
    print(json.dumps(vt_result, indent=2) if vt_result else "No data")

    print(Fore.CYAN + f"[TEST] AbuseIPDB on {test_ip}:" + Style.RESET_ALL)
    abuse_result = check_abuseipdb(test_ip)
    print(json.dumps(abuse_result, indent=2) if abuse_result else "No data")


# === Test Runner ===
if __name__ == "__main__":
    test_api_queries()