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
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Initialize colorama
init()

# === CONFIG ===
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
# === Dynamic Scan Directories ===
if os.name == "nt":  # Windows
    SCAN_DIRS = [
        os.path.expandvars(r"%USERPROFILE%\\AppData\\Local\\Logs"),
        r"C:\\Users",
        r"C:\\ProgramData",
        r"C:\\Windows\\System32\\LogFiles"
    ]
else:  # Unix/Linux/macOS
    SCAN_DIRS = [
        "/var/log",              # System logs
        "/home",                 # All user home dirs
        str(Path.home()),        # Current user's home
        "/etc",                  # Config files
        "/opt",                  # Optional software (may include services)
        "/usr/local/var/log"     # Additional logs
    ]
ALERT_FILE = "alerts.txt"
RESULT_FILE = "results.txt"
SCAN_DB_FILE = "scan_db.json"
IOC_DB_FILE = "ioc_db.json"

# === REGEX ===
IP_REGEX = r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|...|za|zm|zw|հայ|বাংলা)\b"
HASH_REGEX = r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b"

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
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # Extract malicious count
            return data['data']['attributes']['last_analysis_stats']['malicious']
        elif response.status_code == 404:
            # Not found on VT, likely clean or unknown
            return 0
        else:
            # Handle other API errors
            print(Fore.BLUE + f"[VT] Error {response.status_code}: Failed to query {ioc}" + Style.RESET_ALL)
            return None
    except requests.RequestException as e:
        # Handle connection errors
        print(Fore.BLUE + f"[VT] Connection error: {e}" + Style.RESET_ALL)
        input("Press Enter to continue...") # Pause on error
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
            data = response.json()
            # Extract abuse confidence score
            return data["data"]["abuseConfidenceScore"]
        else:
            # Handle API errors
            print(Fore.BLUE + f"[AbuseIPDB] Error {response.status_code} while checking {ip}" + Style.RESET_ALL)
            input("Press Enter to continue...") # Pause on error
            return None
    except requests.RequestException as e:
         # Handle connection errors
        print(Fore.BLUE + f"[AbuseIPDB] Connection error: {e}" + Style.RESET_ALL)
        return None
    
# === Write aler to results.txt ===
def log_result(alert):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {alert}\n"
    with open(RESULT_FILE, "a") as rf:
        rf.write(entry)

# === Request Admin Privileges ===
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# === Check if the IOC is valid ===  
def is_valid_ioc(ioc):
    ioc = ioc.strip().lower()

    # Skip obvious file extensions and junk
    bad_exts = [
        ".exe", ".dll", ".sys", ".xml", ".vdi", ".tmp", ".pxe", ".pku", ".ttf",
        ".png", ".bat", ".ini", ".ush", ".ddp", ".txt", ".row"
    ]
    if any(ioc.endswith(ext) for ext in bad_exts):
        return False
    
    # Skip things that look like file sizes or version numbers
    if re.match(r"^\d+(\.\d+)?(gb|mb|kb|mb)?$", ioc):
        return False
    if re.match(r"^\d+\.\d+\.\d+$", ioc): 
        return False
    
     # Skip time strings like 49.74s or 0.00s
    if re.match(r"^\d+(\.\d+)?s$", ioc):
        return False
    
    # Skip IPs like 0.0.0 or invalid formatting
    if re.fullmatch(IP_REGEX, ioc):
        try:
            ip = ipaddress.ip_address(ioc)
            if ip.is_unspecified or ip.is_reserved or ip.is_loopback:
                return False
        except ValueError:
            return False

    # Skip dates  
    if re.match(r"^\d{4}\.\d{2}\.\d{2}$", ioc):
        return False
    
    # Skip ports/IP:port like 0.0.0.0:0
    if ":" in ioc and re.search(r"\d+\.\d+\.\d+\.\d+:\d+", ioc):
        return False
    
    # Skip hex-looking values with dots (like "731c.c04")
    if re.match(r"^[a-f0-9]+\.[a-f0-9]+$", ioc):
        return False
    
    # Skip known config/engine flags (e.g., "r.SSR")
    if re.match(r"^r\.[a-z0-9\.]+$", ioc):
        return False
    
    # Skip anything too short (e.g., random log noise)
    if len(ioc) < 5:
        return False
        
    # Skip values without a dot (unless it's a hash)
    if "." not in ioc and not re.fullmatch(HASH_REGEX, ioc):
        return False
    
    return True

# === Check if the domain is valid ===
def is_valid_domain(domain):
    return not domain.endswith(('.', '-')) and '.' in domain

# === Scan logs ===
def scan_logs():
    scan_db = load_jason_file(SCAN_DB_FILE)
    ioc_db = load_jason_file(IOC_DB_FILE)

    for base_dir in SCAN_DIRS:
        for path in Path(base_dir).rglob("*.log"):
            try:
                path_str = str(path)
                size = os.path.getsize(path)

                # Skip if file hasn't changed
                if path_str in scan_db and scan_db[path_str] == size:
                    print(f"[~] Skipping unchanged file: {path_str}")
                    continue

                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    iocs = set()
                    iocs.update(re.findall(IP_REGEX, content))
                    iocs.update(re.findall(DOMAIN_REGEX, content))
                    iocs.update(re.findall(HASH_REGEX, content))

                    # Filter out junk
                    iocs = {ioc for ioc in iocs if is_valid_ioc(ioc)}

                    for ioc in iocs:
                        if ioc in ioc_db:
                            continue  # Already processed

                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        alert = None
                        vt_score = None
                        abuse_score = None

                        if re.fullmatch(IP_REGEX, ioc) and not is_internal_ip(ioc):
                            vt_score = check_virustotal(ioc)
                            abuse_score = check_abuseipdb(ioc)

                            alert = {
                                "type": "ip",
                                "ioc": ioc,
                                "virustotal_malicious": vt_score,
                                "abuseipdb_score": abuse_score,
                                "source_file": path_str,
                                "timestamp": timestamp
                            }

                        elif re.fullmatch(DOMAIN_REGEX, ioc) and is_valid_domain(ioc):
                            vt_score = check_virustotal(ioc, ioc_type="domain")

                            alert = {
                                "type": "domain",
                                "ioc": ioc,
                                "virustotal_malicious": vt_score,
                                "source_file": path_str,
                                "timestamp": timestamp
                            }

                        elif re.fullmatch(HASH_REGEX, ioc):
                            vt_score = check_virustotal(ioc, ioc_type="file")

                            alert = {
                                "type": "hash",
                                "ioc": ioc,
                                "virustotal_malicious": vt_score,
                                "source_file": path_str,
                                "timestamp": timestamp
                            }

                        # Save and log only if alert is created
                        if alert:
                            ioc_db[ioc] = alert
                            log_result(json.dumps(alert))  # Save to results.txt
                            save_jason_file(IOC_DB_FILE, ioc_db)

                        time.sleep(1.2)  # Rate limiting

                # Update scan DB to skip next time
                scan_db[path_str] = size
                save_jason_file(SCAN_DB_FILE, scan_db)

            except Exception as e:
                print(f"[!] Failed to scan {path}: {e}")
    print(Fore.GREEN + "[+] Scan complete." + Style.RESET_ALL)

# === Main Execution Block ===
if __name__ == "__main__":
    # Check for admin privileges and relaunch of needed
    if not is_admin():
        print("[!] Admin privileges required. Relaunching as admin...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit() # Print startup message
    print("[+] Starting IOC scan in directories:")
    for d in SCAN_DIRS:
        print("   ", d)
    
    # Start the Scan
    scan_logs()

    #Print completion message
    print("[+] Alerts saved to", ALERT_FILE)
    print("[+] Detailed results saved to", RESULT_FILE)
    