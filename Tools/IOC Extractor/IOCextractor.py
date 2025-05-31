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
    pass
def save_csv_file(path, data):
    pass


# === IP Check ===
def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return True