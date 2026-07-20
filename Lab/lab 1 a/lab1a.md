# Lab 1a SOC Analysis Report

**Student Name:** Shachar Laria  
**Student ID:** 214399198  
**Date:** 20/07/2026  

---

## Detection Findings

### Finding 1
* **Activity:** Possible Brute-Force Login Attempt
* **Source IP:** `172.18.0.22` (and `192.168.1.50`)
* **Evidence:** 9 failed password events were detected from `172.18.0.22`, and 3 failed password events were detected from `192.168.1.50` targeting systemic accounts.
* **MITRE ATT&CK Technique:** Brute Force ([T1110](https://attack.mitre.org/techniques/T1110/))
* **Tactic:** Credential Access
* **Why is this finding suspicious?**  
  A high volume of consecutive failed login attempts within a short timeframe indicates an automated tool or script attempting to guess user credentials (specifically targeting the `root` account). This behavior represents a classic unauthorized access attempt designed to compromise system accounts and achieve initial access or privilege escalation.

### Finding 2
* **Activity:** Possible Network Service Discovery
* **Source IP:** `172.18.0.33`
* **Evidence:** Network scan detected from `172.18.0.33` sequentially probing management and communication ports `21` (FTP), `22` (SSH), `23` (Telnet), and `25` (SMTP).
* **MITRE ATT&CK Technique:** Network Service Discovery ([T1046](https://attack.mitre.org/techniques/T1046/))
* **Tactic:** Discovery
* **Why is this finding suspicious?**  
  The source IP is actively scanning multiple well-known service ports in a tight time window. This internal reconnaissance behavior is typical of an attacker mapping out the network topology to identify active services, network daemons, and potential vulnerabilities for subsequent lateral movement.

---

## Containerization

**Explain briefly why Docker was used even though the laboratory did not use cloud services:**  
Docker ensures complete environment reproducibility and isolation. It guarantees that the detection script (`detector.py`), its dependencies (like STIX parsing libraries), and the local MITRE ATT&CK JSON database run identically on any host machine (Windows, macOS, or Linux) without needing to manually install Python packages or alter local host system configurations.

---

## Reflection

### Why is a detection finding not proof of an attack?
A detection finding simply flags an event that matches a specific signature or pre-defined rule (heuristic). Legitimate administrative tools, automated system updates, or heavy network troubleshooting can mimic malicious patterns (e.g., an IT administrator running an authorized bulk deployment script or an internal vulnerability scanner performing a scheduled audit), meaning a finding requires context and human verification to prove malicious intent.

### What additional logs would help confirm the findings?
To fully confirm these findings, analysts would benefit from:
* **Sysmon Logs (Event ID 1):** To track process ancestry and see what applications were spawned during or right after the login attempts.
* **Network Flow Logs (NetFlow):** To verify if external data transfers or outbound connections were made by the compromised assets.
* **Host Authentication Logs (Event ID 4624 / 4625):** To inspect extended authentication details, logon types, and verify if any subsequent attempt resulted in a successful login (`Event ID 4624`).

### What could cause a false positive?
Automated backup systems, centralized endpoint management software (like SCCM, Ansible, or specialized software deployment agents), and scheduled internal IT maintenance scripts frequently run bulk administrative tasks, rotate logs, or check service status across multiple ports. If the detection rules are written too broadly, these legitimate administrative actions will trigger false positive alerts.
