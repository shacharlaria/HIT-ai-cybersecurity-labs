
# Lab 1 — Cyber Threat Intelligence (CTI) Report Mapping to MITRE ATT&CK

## 👥 Group Members
* **Shachar Laria**

---

## 🔗 Source CTI Report
* **Report Title:** LockBit 3.0 Ransomware Analysis and Cyber Threat Intelligence Mitigation Guide
* **Link:** [CISA & FBI Joint Cybersecurity Advisory on LockBit](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a)

---

## 📝 Short Attack Summary
LockBit 3.0 operates as a Ransomware-as-a-Service (RaaS) model and represents one of the most destructive ransomware threats globally. The attack chain typically begins with threat actors gaining initial access to the target network through spearphishing emails containing malicious attachments or by exploiting public-facing applications. Once inside, the attackers execute malicious PowerShell scripts and deploy customized beacons to establish command and control. They systematically escalate privileges, discover network resources, and disable local security software to avoid detection. Before deploying the final encryption payload, the attackers exfiltrate sensitive corporate data to double-extort the victim. This threat matters significantly because LockBit continuously evolves its tactics, targeting critical infrastructure and forcing organizations into operational paralysis.

---

## 📊 Attack Sequence
Below is the sequential flow of the behavioral chain observed during the LockBit 3.0 intrusion:

1. **Initial Access:** Delivery of spearphishing emails with malicious ZIP attachments to corporate targets.
2. **Execution:** User interacts with the attachment, triggering the execution of a malicious macro/script.
3. **Persistence & Defense Evasion:** Modification of registry keys to maintain access and terminating local antivirus processes.
4. **Credential Access:** Dumping LSASS memory to extract administrative credentials.
5. **Discovery & Lateral Movement:** Scanning the local network using PowerShell to identify domain controllers and active shares.
6. **Exfiltration & Impact:** Exfiltrating sensitive organization files followed by the execution of the LockBit 3.0 ransomware payload to encrypt local drives.

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | Behavior from Report | MITRE ATT&CK Link |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Phishing: Spearphishing Attachment (T1566.001) | Threat actors sent targeted emails containing malicious ZIP archives to corporate mailboxes. | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) |
| **Execution** | Command and Scripting Interpreter: PowerShell (T1059.001) | The attack payload utilized obfuscated PowerShell commands to download secondary stagers. | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Defense Evasion** | Impair Defenses: Disable or Modify Tools (T1562.001) | LockBit actively stopped automated security services, event logging, and disabled Windows Defender. | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |
| **Credential Access** | OS Credential Dumping: LSASS Memory (T1003.001) | Attackers deployed publicly available tools to dump the LSASS process memory and harvest cleartext credentials. | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| **Discovery** | System Network Configuration Discovery (T1016) | Executed commands like `net view` and custom scripts to map out active network shares and active directory structure. | [T1016](https://attack.mitre.org/techniques/T1016/) |
| **Impact** | Data Encrypted for Impact (T1486) | The ransomware encrypted user files across the endpoints and network shares, appending the LockBit extension. | [T1486](https://attack.mitre.org/techniques/T1486/) |

---

## 💡 Insights / What You Learned
* Mapping a real-world threat actor report to the MITRE ATT&CK framework allows defensive teams to visually identify gaps in their existing security controls, shifting the perspective from reactive containment to proactive hunting.
* We learned that modern ransomware groups heavily rely on native administrative utilities (like PowerShell) to blend in with legitimate network traffic, which underscores the necessity of strict endpoint monitoring and logging.
