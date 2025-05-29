# 🧪 Network Forensics Case – 2025-01-22

**Source:** [Malware Traffic Analysis – 2025-01-22](https://www.malware-traffic-analysis.net/2025/01/22/index.html)  
**PCAP File:** 2025-01-22-traffic-analysis-exercise.pcap  
**Tool Used:** Wireshark  
**Analyst:** Alex Bondarchuk  
**Date Analyzed:** 2025-05-28  

---

## 🎯 Objective

Analyze the network traffic to determine the infected Windows client identity, trace malicious domains, extract C2 indicators, and document malicious behavior.

---

## 🧩 Question: What is the IP address of the infected Windows client?

**Answer:** `10.1.17.215`

### 🧠 Method:
- Observed full DHCP handshake assigning `10.1.17.215` from `10.1.17.2`.
- Confirmed this as the host because 40.7% of total packets originate from `10.1.17.215`, and 58.4% are addressed to it.

---

## 🧩 Question: What is the MAC address of the infected Windows client?

**Answer:** `00:d0:b7:26:4a:74`

### 🧠 Method:
- Applied ARP filter and searched for activity from `10.1.17.215`.
- Found ARP response from `10.1.17.215` reporting its MAC as `00:d0:b7:26:4a:74`.

---

## 🧩 Question: What is the host name of the infected Windows client?

**Answer:** `DESKTOP-L8C5GSJ`

### 🧠 Method:
- Host name was visible during the DHCP handshake phase.
- Also corroborated by NetBIOS and Kerberos packets later in the capture.

---

## 🧩 Question: What is the user account name from the infected Windows client?

**Answer:** `shutchenson`

### 🧠 Method:
- DHCP and NBNS did not yield a user name.
- Applied `kerberos.CNameString` filter.
- Used "Apply as Column" on the field and found several packets showing `shutchenson` associated with `DESKTOP-L8C5GSJ`.

---

## 🧩 Question: What is the likely domain name for the fake Google Authenticator page?

**Answer:** `authenticatoor.org`

### 🧠 Method:
- Based on the infection scenario involving a search for "Google Authenticator."
- Filtered DNS queries for keywords `google` and `authenticator`.
- Found two suspicious domains: `google-authenticator.burleson-appliance.net` and `authenticatoor.org`.
- Timing and packet flow suggest `burleson-appliance.net` redirected to `authenticatoor.org`, which ultimately hosted the fake login page.

---

## 🧩 Question: What are the IP addresses used for C2 servers for this infection?

**Answer:** `45.125.66.32`, `5.252.153.241`

### 🧠 Method:
- Used **Statistics → Conversations** in Wireshark.
- Identified `45.125.66.32` and `5.252.153.241` with the highest packet counts, longest durations, and most bytes sent/received.
- Inspected TCP streams and confirmed malicious behavior.

---

## 🔬 TCP Stream Analysis: 5.252.153.241

- Accessed API endpoint: `/api/file/get-file/264872` — likely file retrieval service.
- User-Agent: `MSIE 7.0` (a legacy browser) on `Windows NT 10.0` — clear mismatch.
  - Likely spoofed to evade signature detection.
- Loaded decoy site: `azure.microsoft.com` — likely to create legitimacy illusion.
- Downloaded and executed a PowerShell script from: `http://5.252.153.241:80/api/file/get-file/29842.ps1`
- This confirms remote code execution (RCE) via PowerShell.

---

## 📌 Indicators of Compromise (IOCs)

| Type        | Value                             |
|-------------|-----------------------------------|
| IP Address  | `5.252.153.241`, `45.125.66.32`   |
| Domain      | `authenticatoor.org`             |
| File Path   | `/api/file/get-file/29842.ps1`   |
| User Name   | `shutchenson`                    |
| Host Name   | `DESKTOP-L8C5GSJ`                |
| MAC Address | `00:d0:b7:26:4a:74`              |

---

## 🛠️ Tools Used

- Wireshark
- Display filters
- Follow TCP stream
- Conversation analysis
- DHCP, DNS, HTTP, ARP, Kerberos protocol layers
- Malware-Traffic-Analysis.net case file
