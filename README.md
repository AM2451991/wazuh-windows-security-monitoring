**\*\*# Wazuh Windows Security Monitoring \\\& Detection Lab\*\***







**\*\*## Project Overview\*\***







**\*\*This project demonstrates a local Security Operations Center (SOC) monitoring environment using \\\*\\\*Wazuh\\\*\\\* to collect and analyze Windows security telemetry.\*\***







**\*\*The lab focuses on Windows process-creation monitoring, PowerShell activity detection, custom Wazuh detection rules, alert investigation, and MITRE ATT\\\&CK mapping.\*\***







**\*\*### Objective\*\***







**\*\*Build practical experience with the SOC workflow:\*\***







**\*\*\\\*\\\*Collect → Detect → Investigate → Analyze → Map → Document\\\*\\\*\*\***







**\*\*---\*\***







**\*\*## Lab Architecture\*\***







**\*\*```text\*\***



**\*\*Windows 11 Endpoint\*\***



**\&#x20;       \*\*│\*\***



**\&#x20;       \*\*│ Windows Security Events\*\***



**\&#x20;       \*\*│ Event ID 4688\*\***



**\&#x20;       \*\*▼\*\***



**\&#x20;  \*\*Wazuh Agent\*\***



**\&#x20;       \*\*│\*\***



**\&#x20;       \*\*▼\*\***



**\&#x20;  \*\*Wazuh Manager\*\***



**\&#x20;       \*\*│\*\***



**\&#x20;       \*\*▼\*\***



**\&#x20;  \*\*Wazuh Rules Engine\*\***



**\&#x20;       \*\*│\*\***



**\&#x20;       \*\*├── Built-in Rule 67027\*\***



**\&#x20;       \*\*│\*\***



**\&#x20;       \*\*└── Custom Rule 100100\*\***



**\&#x20;               \*\*│\*\***



**\&#x20;               \*\*▼\*\***



**\&#x20;         \*\*Level 10 Alert\*\***



**\&#x20;               \*\*│\*\***



**\&#x20;               \*\*▼\*\***



**\&#x20;      \*\*Wazuh Dashboard\*\***



**\*\*```\*\***







**\*\*### Environment\*\***







**\*\*| Component        | Configuration        |\*\***



**\*\*| ---------------- | -------------------- |\*\***



**\*\*| Wazuh Manager    | Wazuh 4.14.8         |\*\***



**\*\*| Wazuh Agent      | Windows 11           |\*\***



**\*\*| Agent Name       | `Cloud-Security-Lab` |\*\***



**\*\*| Wazuh Manager IP | `192.168.56.102`     |\*\***



**\*\*| Network          | VirtualBox Host-Only |\*\***



**\*\*| Virtualization   | Oracle VirtualBox    |\*\***







**\*\*---\*\***







**\*\*## 1. Wazuh Environment\*\***







**\*\*A Wazuh virtual appliance was deployed in VirtualBox and configured as the central monitoring server.\*\***







**\*\*The environment includes:\*\***







**\*\*\\\* Wazuh Manager\*\***



**\*\*\\\* Wazuh Indexer\*\***



**\*\*\\\* Wazuh Dashboard\*\***



**\*\*\\\* Windows 11 endpoint with Wazuh agent\*\***







**\*\*The Wazuh virtual machine was configured with:\*\***







**\*\*\\\* \\\*\\\*6 GB RAM\\\*\\\*\*\***



**\*\*\\\* \\\*\\\*4 processors\\\*\\\*\*\***



**\*\*\\\* \\\*\\\*25 GB disk\\\*\\\*\*\***







**\*\*The Wazuh server communicates with the Windows endpoint through a VirtualBox Host-Only network.\*\***







**\*\*---\*\***







**\*\*## 2. Windows Agent\*\***







**\*\*The Windows 11 endpoint was registered with Wazuh using the agent name:\*\***







**\*\*```text\*\***



**\*\*Cloud-Security-Lab\*\***



**\*\*```\*\***







**\*\*The endpoint was successfully connected to the Wazuh manager and began forwarding Windows security telemetry.\*\***







**\*\*---\*\***







**\*\*## 3. Windows Security Monitoring\*\***







**\*\*The primary telemetry used in this project is:\*\***







**\*\*```text\*\***



**\*\*Event ID: 4688\*\***



**\*\*Event: A new process has been created\*\***



**\*\*```\*\***







**\*\*Windows Event ID 4688 provides process execution information such as:\*\***







**\*\*\\\* User account\*\***



**\*\*\\\* Process name\*\***



**\*\*\\\* Parent process\*\***



**\*\*\\\* Process ID\*\***



**\*\*\\\* Command line\*\***



**\*\*\\\* Logon information\*\***



**\*\*\\\* Token elevation information\*\***







**\*\*This information can help SOC analysts identify suspicious process execution and command-line activity.\*\***







**\*\*---\*\***







**\*\*## 4. Initial Wazuh Detection\*\***







**\*\*Wazuh successfully received Windows Event ID 4688 events from the endpoint.\*\***







**\*\*The built-in Wazuh rule used as the parent detection was:\*\***







**\*\*```text\*\***



**\*\*Rule ID: 67027\*\***



**\*\*Level: 3\*\***



**\*\*Description: A process was created.\*\***



**\*\*```\*\***







**\*\*The Windows EventChannel decoder processed the Windows security event.\*\***







**\*\*---\*\***







**\*\*# 5. Custom PowerShell Detection\*\***







**\*\*## Detection Objective\*\***







**\*\*A custom Wazuh rule was created to detect PowerShell execution containing the:\*\***







**\*\*```text\*\***



**\*\*-EncodedCommand\*\***



**\*\*```\*\***







**\*\*parameter.\*\***







**\*\*Encoded PowerShell commands can conceal the readable contents of a command line and therefore provide useful telemetry for security investigation.\*\***







**\*\*The lab uses a controlled and harmless test command for validation.\*\***







**\*\*---\*\***







**\*\*## Custom Wazuh Rule\*\***







**\*\*The final working rule is:\*\***







**\*\*```xml\*\***



**\*\*<group name="windows,powershell,custom,">\*\***



**\&#x20; \*\*<rule id="100100" level="10">\*\***



**\&#x20;   \*\*<if\\\_sid>67027</if\\\_sid>\*\***



**\&#x20;   \*\*<field name="win.eventdata.commandLine">-EncodedCommand</field>\*\***



**\&#x20;   \*\*<description>Encoded PowerShell command detected.</description>\*\***



**\&#x20;   \*\*<mitre>\*\***



**\&#x20;     \*\*<id>T1059.001</id>\*\***



**\&#x20;     \*\*<id>T1027</id>\*\***



**\&#x20;   \*\*</mitre>\*\***



**\&#x20; \*\*</rule>\*\***



**\*\*</group>\*\***



**\*\*```\*\***







**\*\*### Detection Logic\*\***







**\*\*The rule:\*\***







**\*\*1. Uses Wazuh rule \\\*\\\*67027\\\*\\\* as the parent event.\*\***



**\*\*2. Examines the Windows `commandLine` field.\*\***



**\*\*3. Searches for the `-EncodedCommand` parameter.\*\***



**\*\*4. Generates a custom \\\*\\\*Level 10\\\*\\\* alert.\*\***



**\*\*5. Maps the detection to relevant MITRE ATT\\\&CK techniques.\*\***







**\*\*---\*\***







**\*\*# 6. MITRE ATT\\\&CK Mapping\*\***







**\*\*### T1059.001 — PowerShell\*\***







**\*\*The detection identifies PowerShell execution through Windows process-creation telemetry.\*\***







**\*\*### T1027 — Obfuscated/Compressed Files and Information\*\***







**\*\*The use of an encoded PowerShell command is treated as an obfuscation indicator that warrants investigation.\*\***







**\*\*> The presence of an encoded command does not by itself prove malicious activity. An analyst must investigate the command, user, parent process, endpoint, and surrounding activity.\*\***







**\*\*---\*\***







**\*\*# 7. Controlled Detection Test\*\***







**\*\*A controlled PowerShell command was executed on the Windows lab endpoint using the `-EncodedCommand` parameter.\*\***







**\*\*The test command was designed to produce harmless output and was used solely to validate the detection.\*\***







**\*\*Windows generated:\*\***







**\*\*```text\*\***



**\*\*Event ID: 4688\*\***



**\*\*A new process has been created\*\***



**\*\*```\*\***







**\*\*The event was forwarded to Wazuh for analysis.\*\***







**\*\*---\*\***







**\*\*# 8. Alert Investigation\*\***







**\*\*The event was initially identified by the built-in process-creation rule:\*\***







**\*\*```text\*\***



**\*\*Rule ID: 67027\*\***



**\*\*Level: 3\*\***



**\*\*Description: A process was created.\*\***



**\*\*```\*\***







**\*\*The custom rule then evaluated the Windows command-line field.\*\***







**\*\*When the command contained:\*\***







**\*\*```text\*\***



**\*\*-EncodedCommand\*\***



**\*\*```\*\***







**\*\*the custom rule generated:\*\***







**\*\*```text\*\***



**\*\*Rule ID: 100100\*\***



**\*\*Level: 10\*\***



**\*\*Description: Encoded PowerShell command detected.\*\***



**\*\*```\*\***







**\*\*### Detection Flow\*\***







**\*\*```text\*\***



**\*\*PowerShell Execution\*\***



**\&#x20;       \*\*↓\*\***



**\*\*Windows Event ID 4688\*\***



**\&#x20;       \*\*↓\*\***



**\*\*Windows EventChannel Decoder\*\***



**\&#x20;       \*\*↓\*\***



**\*\*Wazuh Rule 67027\*\***



**\&#x20;       \*\*↓\*\***



**\*\*Custom Rule 100100\*\***



**\&#x20;       \*\*↓\*\***



**\*\*Level 10 Alert\*\***



**\&#x20;       \*\*↓\*\***



**\*\*SOC Investigation\*\***



**\*\*```\*\***







**\*\*---\*\***







**\*\*# 9. SOC Analyst Investigation Approach\*\***







**\*\*If this alert occurred in a production environment, it would not automatically be treated as a confirmed security incident.\*\***







**\*\*The analyst would investigate:\*\***







**\*\*\\\* Which user executed PowerShell?\*\***



**\*\*\\\* What was the full command line?\*\***



**\*\*\\\* What was the parent process?\*\***



**\*\*\\\* Was the activity expected or authorized?\*\***



**\*\*\\\* Was the endpoint production or non-production?\*\***



**\*\*\\\* What did the encoded command contain?\*\***



**\*\*\\\* Were network connections associated with the process?\*\***



**\*\*\\\* Did the process create or modify files?\*\***



**\*\*\\\* Were additional suspicious events generated?\*\***



**\*\*\\\* Was the activity part of an administrative or automation task?\*\***







**\*\*The analyst would correlate the available evidence before determining the appropriate response.\*\***







**\*\*---\*\***







**\*\*# 10. Evidence\*\***







**\*\*The successful Level 10 detection is captured in:\*\***







**\*\*```text\*\***



**\*\*Evidence/wazuh-encoded-powershell-level10-alert.png\*\***



**\*\*```\*\***







**\*\*The evidence demonstrates:\*\***







**\*\*\\\* Windows PowerShell process creation\*\***



**\*\*\\\* Encoded command-line activity\*\***



**\*\*\\\* Wazuh detection\*\***



**\*\*\\\* Custom rule `100100`\*\***



**\*\*\\\* Level 10 alert\*\***



**\*\*\\\* Encoded PowerShell detection message\*\***







**\*\*---\*\***







**\*\*# 11. Skills Demonstrated\*\***







**\*\*This project demonstrates hands-on experience with:\*\***







**\*\*\\\* Wazuh SIEM monitoring\*\***



**\*\*\\\* Windows Security Event Logs\*\***



**\*\*\\\* Windows Event ID 4688\*\***



**\*\*\\\* PowerShell security monitoring\*\***



**\*\*\\\* Command-line analysis\*\***



**\*\*\\\* Custom Wazuh detection rules\*\***



**\*\*\\\* Rule chaining\*\***



**\*\*\\\* Alert triage\*\***



**\*\*\\\* Event investigation\*\***



**\*\*\\\* MITRE ATT\\\&CK mapping\*\***



**\*\*\\\* Virtualized security labs\*\***



**\*\*\\\* SOC detection engineering fundamentals\*\***







**\*\*---\*\***







**\*\*# 12. Project Outcome\*\***







**\*\*The lab successfully demonstrated an end-to-end endpoint detection workflow:\*\***







**\*\*```text\*\***



**\*\*Windows Endpoint\*\***



**\&#x20;     \*\*↓\*\***



**\*\*Security Telemetry\*\***



**\&#x20;     \*\*↓\*\***



**\*\*Wazuh Agent\*\***



**\&#x20;     \*\*↓\*\***



**\*\*Wazuh Manager\*\***



**\&#x20;     \*\*↓\*\***



**\*\*Windows Event ID 4688\*\***



**\&#x20;     \*\*↓\*\***



**\*\*Custom Detection Rule\*\***



**\&#x20;     \*\*↓\*\***



**\*\*Level 10 Alert\*\***



**\&#x20;     \*\*↓\*\***



**\*\*MITRE ATT\\\&CK Mapping\*\***



**\&#x20;     \*\*↓\*\***



**\*\*SOC Investigation\*\***



**\*\*```\*\***







**\*\*The project provided hands-on experience in transforming Windows endpoint telemetry into a targeted security detection using Wazuh.\*\***







**\*\*---\*\***







**\*\*## Disclaimer\*\***







**\*\*This project was conducted entirely within a controlled local virtual lab environment.\*\***







**\*\*The PowerShell activity used for validation was intentionally generated for detection testing and does not represent real malicious activity.\*\***

