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
VIRUSTOTAL_API_KEY = "..."
ABUSEIPDB_API_KEY = "..."
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
    


# === Test Runner ===
if __name__ == "__main__":
    print(Fore.CYAN + "[TEST] Running file I/O tests..." + Style.RESET_ALL)

    sample_json = {"ips": ["8.8.8.8", "1.1.1.1"], "status": "test"}
    sample_txt = ["line one", "line two", "line three"]
    sample_csv = [["header1", "header2"], ["row1", "row2"], ["row3a", "row3b"]]

    # Save
    save_jason_file(json_path, sample_json)
    save_txt_file(txt_path, sample_txt)
    save_csv_file(csv_path, sample_csv)

    # Load
    loaded_json = load_jason_file(json_path)
    loaded_txt = load_txt_file(txt_path)
    loaded_csv = load_csv_file(csv_path)

    # Verify
    print("Loaded JSON:", loaded_json)
    print("Loaded TXT:", loaded_txt)
    print("Loaded CSV:", loaded_csv)

    assert loaded_json == sample_json, "❌ JSON Mismatch"
    assert loaded_txt == sample_txt, "❌ TXT Mismatch"
    assert loaded_csv == sample_csv, "❌ CSV Mismatch"

    print(Fore.GREEN + "[PASS] All file I/O functions working correctly!" + Style.RESET_ALL)