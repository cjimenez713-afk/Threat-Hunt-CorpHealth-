# Threat Hunt Report: CorpHealth — Traceback
<img width="740" height="740" alt="AN7BsVBtkGtfuVV1cqwny5KN6hlEwljztyQu_VS9okJvuwGaajuD2yqKCj28BF1nOPGJmJ5JpWsPS_0Ju3s3DsDGkFoQ9YGmjSIZxihRPdd-55_dYJzoUhQKBGUm" src="https://github.com/user-attachments/assets/4cd9d871-3327-45e0-91d1-434ec1998d2b" />

---

***Analyst:*** Christopher Jimenez

***Date Completed:*** 2026-01-18

***Environment Investigated:*** ch-ops-wks02 (with pivots to internal host 10.168.0.6)

***Timeframe:*** Mid-November – Early December 2025 (key activity 2025-11-23 → 2025-11-30)

---
# Table of Contents

1. [Scenario Overview](#scenario-overview)

2. [Executive Summary](#executive-summary)

3. [Completed Flags](#completed-flags)

4. [Flag-by-Flag + KQL](#flag-by-flag) 

5. [Timeline](#timeline)

6. [MITRE ATT&CK Mapping](#mitre-att&ck-mapping)

7. [Indicators of Compromise (IoCs)](#indicators-of-compromise-(iocs))

8. [Custom Detection Rule Ideas](#custom-detection-rule-ideas)

9. [Remediation & Containment Checklist](#remediation-&-containment-checklist)

10. [Lessons Learned](#lessons-learned)

11. [Final Recommendation](#final-recommendation)


---
## 🧠 Scenario Overview

Your organization recently completed a phased deployment of an internal platform known as CorpHealth — a lightweight system monitoring and maintenance framework designed to: 
 
- Track endpoint stability and performance
- Run automated post-patch health checks
- Collect system diagnostics during maintenance windows
- Reduce manual workload for operations teams 

CorpHealth operates using a mix of scheduled tasks, background services, and diagnostic scripts deployed across operational workstations. To support this, IT provisioned a dedicated operational account.

This account was granted local administrator privileges on specific systems in order to: 

- Register scheduled maintenance tasks
- Install and remove system services
- Write diagnostic and configuration data to protected system locations
- Perform controlled cleanup and telemetry operations 

It was designed to be used only through approved automation frameworks, not through interactive sign-ins.


---

## 🎯 Executive Summary

The investigation discovered ch-ops-wks02 exhibited multi-stage suspicious behavior during an off-hours window in late November 2025:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;A unique maintenance script (MaintenanceRunner_Distributed.ps1) ran outside of approved automation and attempted an outbound connection (beaconing).
The script successfully connected to an external source; soon after, staged diagnostic exports were created in CorpHealth folders and temporary user locations.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Registry artifacts and a scheduled task (nonstandard) were created; a short-lived Run-key value was added then removed.
A token modification (privilege simulation) and a PowerShell -EncodedCommand were observed.
The host used 'curl.exe' to fetch 'revshell.exe' from an ngrok tunnel (remote access), which was executed via explorer.exe, and copied it into the Startup folder to maintain access (persistence).
Remote session metadata shows a remote session device label 对手 and remote IPs including 104.164.168.17 (initial login origin; geolocated to Vietnam), 100.64.100.6 (remote session IP), and an internal pivot host 10.168.0.6.
The activity chain indicates hands-on-keyboard behavior initiating from a remote session, credential use/harvesting, staging for exfiltration, and a remote foothold via a reverse shell.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Conclusion: The observed behavior is consistent with misuse of privileged automation and active malicious activity (credential harvesting, staging, ingress of a reverse shell, persistence). This is beyond benign automation and should be escalated to incident response.


---

## ✅ Completed Flags

| Flag |	Objective |	Value |
|------|------------|-------|
Start	| First suspicious machine |	ch-ops-wks02
1	| Unique maintenance file	| MaintenanceRunner_Distributed.ps1
2	| First outbound beacon timestamp	| 2025-11-23T03:46:08.400686Z
3	| Beacon destination (IP:Port)	| 127.0.0.1:8080
4	| Successful beacon latest timestamp |	2025-11-30T01:03:17.6985973Z
5	| First staged artifact (path)	| C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv
6	| SHA-256 of staged file	| 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8
7	| Duplicate staged artifact (path)	| C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv
8	| Suspicious registry key	| HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent
9	| Scheduled task created	| HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64
10| Run key value name (ephemeral persistence)	| MaintenanceRunner
11|	First ConfigAdjust (privilege) event timestamp	| 2025-11-23T03:47:21.8529749Z
12|	AV exclusion attempt path	| C:\ProgramData\Corp\Ops\staging
13|	First decoded EncodedCommand	Write-Output | 'token-6D5E4EE08227'
14|	InitiatingProcessId (token modified)	| 4888
15|	SID of modified token	| S-1-5-21-1605642021-30596605-784192815-1000
16|	Ingress tool filename	| revshell.exe
17|	External download URL	| https[:]//unresuscitating-donnette-smothery[.]ngrok-free[.]dev/revshell[.]exe
18|	Process which executed the binary	| explorer.exe
19|	External IP contacted by binary	| 13.228.171.119 (port 11746)
20|	Startup persistence path	| C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe
21|	Remote session device name	| 对手
22|	Remote session IP	| 100.64.100.6
23|	Internal pivot host	| 10.168.0.6
24|	First suspicious logon timestamp	| 2025-11-23T03:08:31.1849379Z
25|	IP of first logon	| 104.164.168.17
26|	Account used for first logon	| chadmin
27|	Attacker geographic region (geo enrichment)	| Vietnam
28|	First process after logon	| explorer.exe
29|	First file accessed by attacker	| CH-OPS-WKS02 user-pass.txt
30|	Next action after reading file	| ipconfig.exe
31|	Next account accessed after recon	| ops.maintenance
---
## Flag-by-Flag (Investigator notes + KQL used)

  For each major investigative step below I include the analyst reasoning and representative KQL you can run in Defender Advanced Hunting. Replace date ranges as needed.

***Starting point*** — Identify the initial system (Flag 0)

Objective: Anchor the investigation on the suspicious device.

Identified: ch-ops-wks02 — a small cluster of events in mid-Nov/early Dec, with Process, Network, File, and Script events.

<img width="743" height="544" alt="where DeviceName startswith che" src="https://github.com/user-attachments/assets/4842ff17-fa28-48f7-a39d-1182919dc872" />

KQL:

``` 
DeviceLogonEvents
| where DeviceName startswith "ch-"
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| project AccountName, DeviceName
```


### Flag 1 — Unique maintenance file

**Objective:** Find script unique to this host — MaintenanceRunner_Distributed.ps1.

<img width="1058" height="508" alt="S-1-5-25-105442021-3059442" src="https://github.com/user-attachments/assets/d86990d9-5d61-45ea-b892-d3df7c54693d" />

KQL:

```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where FolderPath has_any ("script", "maintenance", "tools", "diagnostic")
| where FileName endswith ".ps1"
```

### Flag 2 → 4 — Beaconing behavior (first attempt & success)

**First outbound beacon:** 2025-11-23T03:46:08.400686Z.

<img width="772" height="517" alt="DevicevetworkEvents" src="https://github.com/user-attachments/assets/08e77953-7c08-4559-b507-94b20d0e0e20" />

KQL (network pivot):
```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where InitiatingProcessCommandLine contains "MaintenanceRunner" 

```
**Beacon destination:** 127.0.0.1:8080.

<img width="1083" height="494" alt="Screenshot 2026-01-17 at 8 24 09 PM" src="https://github.com/user-attachments/assets/ff98c493-4a7c-4378-a8e5-3a56dd9cc048" />

```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where InitiatingProcessCommandLine contains "MaintenanceRunner" 
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteIPType, RemotePort, RemoteUrl 
**Successful connection (latest):** 2025-11-30T01:03:17.6985973Z.
```


### Flag 5 → 7 — Staging artifacts and their integrity

**Primary staged file:** C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv

**SHA-256:** 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

<img width="635" height="289" alt="Here better Be Hellecreated cod Folderests containe Boosteri" src="https://github.com/user-attachments/assets/05308496-3669-4a85-8ef2-c837f9604a4b" />

KQL (file find + hash):
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where ActionType == "FileCreated" and FolderPath contains "\\Diagnostics\\"
```


**Duplicate/working copy:** C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv

<img width="912" height="449" alt="Attentype" src="https://github.com/user-attachments/assets/4637a60f-4bd1-455f-b5b7-7f0ddedf81e3" />

```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where ActionType == "FileCreated" and FolderPath contains "inventory"
```

### Flag 8 → 10 — Registry & scheduled-task persistence

**Suspicious registry key:** HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent

<img width="878" height="470" alt="where Devicelane wnch-ops-wks02" src="https://github.com/user-attachments/assets/7284606f-30cd-4623-830d-908d409dc8fa" />

KQL (registry):
```
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
```

**Scheduled Task created:** HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64

<img width="973" height="412" alt="Screenshot 2026-01-17 at 9 10 52 PM" src="https://github.com/user-attachments/assets/bc79c567-e30d-4251-a097-3a0f7c3c776c" />

```
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| where RegistryKey contains "\\Schedule\\"
```

**Run value name (ephemeral):** MaintenanceRunner (created then deleted)

<img width="635" height="447" alt="VDeviceRegistryEvents" src="https://github.com/user-attachments/assets/5ccc8c8b-64f7-4731-8383-485530213285" />


KQL (registry):
```
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-24) .. datetime(2025-11-26))
| where ActionType in ('RegistryKeyCreated','RegistryValueSet','RegistryKeyDeleted')
| project TimeGenerated, DeviceName, RegistryValueName
```

### Flag 11 → 15 — Privilege simulation & token modification

**ConfigAdjust Application event (first):** 2025-11-23T03:47:21.8529749Z

<img width="689" height="396" alt="where DeviceNane an ch-ops-wks02" src="https://github.com/user-attachments/assets/b7f2a085-32fb-463a-b346-3e7b555c404b" />
<img width="860" height="261" alt="V 11232925, 3 4721 852 AM" src="https://github.com/user-attachments/assets/669b4b87-8e23-4bb0-9d4f-1f7cd8e0e3ad" />

```
DeviceEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-26))
| where AdditionalFields has "ConfigAdjust"
```

**Encoded PowerShell decoded:** Write-Output 'token-6D5E4EE08227'

<img width="1058" height="374" alt="Screenshot 2026-01-17 at 11 51 49 PM" src="https://github.com/user-attachments/assets/1a420639-bae2-4514-a1ed-ed7241e82d87" />

KQL (decode EncodedCommand):
```
DeviceProcessEvents 
| where DeviceName == "ch-ops-wks02" and Timestamp between (datetime(2025-11-20) .. datetime(2025-11-26)) and AccountName !contains "system"
| where ProcessCommandLine contains "-EncodedCommand"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
```

**InitiatingProcessId for PrimaryTokenModified:** 4888

<img width="1115" height="436" alt="Screenshot 2026-01-18 at 9 48 53 AM" src="https://github.com/user-attachments/assets/21e6aaa6-c6ff-49a8-bb4b-72d12b43e21f" />

```
DeviceEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-26))
| where AdditionalFields has_any ("tokenChangeDescription","Privileges were added","MaintenanceRunner_Distributed.ps1")
| project TimeGenerated, InitiatingProcessId, AdditionalFields, DeviceName, InitiatingProcessCommandLine
```

**OriginalTokenUserSid:** S-1-5-21-1605642021-30596605-784192815-1000

<img width="1104" height="380" alt="Screenshot 2026-01-18 at 9 53 32 AM" src="https://github.com/user-attachments/assets/f32a8986-ac3c-4cae-bee8-1c6f3de0f750" />

KQL (token change):

```
DeviceEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-26))
| where AdditionalFields has_any ("tokenChangeDescription","Privileges were added","MaintenanceRunner_Distributed.ps1")
| project TimeGenerated, InitiatingProcessId, AdditionalFields, DeviceName, InitiatingProcessCommandLine
```


### Flag 12 — AV exclusion attempt

**Attempted exclusion path:** C:\ProgramData\Corp\Ops\staging

<img width="1051" height="414" alt="Screenshot 2026-01-17 at 11 43 09 PM" src="https://github.com/user-attachments/assets/6e9d4900-be19-4211-b35f-66dcac0a6431" />

KQL (Defender Exclusion Path):
```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02" and Timestamp between (datetime(2025-11-20) .. datetime(2025-11-26))
| where ProcessCommandLine has_any ("Set-MpPreference","Add-MpPreference","-ExclusionPath")
| project Timestamp, DeviceName, FileName, ProcessCommandLine;
```

### Flag 16 → 20 — Ingress of reverse shell & persistence

**Downloaded filename:** revshell.exe

<img width="816" height="441" alt="where Tiedalene befveen (datetise(2025-11-10)   datetise(2825-12-05)1" src="https://github.com/user-attachments/assets/49354ad2-4f1b-4e7b-972a-c8333e89036c" />

**Download URL:** https[:]//unresuscitating-donnette-smothery[.]ngrok-free[.]dev/revshell[.]exe

<img width="596" height="147" alt="ch-ops-wks02" src="https://github.com/user-attachments/assets/3bfa1286-b466-4991-989d-79a9444c8903" />

KQL (download & execution):
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where InitiatingProcessCommandLine contains "curl"
```

**Executed by:** explorer.exe

<img width="641" height="324" alt="DeviceProcessEvents" src="https://github.com/user-attachments/assets/de80e918-af8b-4bfd-b883-913f0e7fa7a2" />

```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where InitiatingProcessCommandLine contains "revshell"
```

**External IP contacted by binary:** 13.228.171.119 (port 11746)

<img width="754" height="460" alt="vDeviceNetworkEvents" src="https://github.com/user-attachments/assets/6f3374a7-1a91-41fd-a741-5cd282ffe34b" />

```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where InitiatingProcessCommandLine contains "revshell" and RemotePort == "11746"
```

**Startup path (persistence):** C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe

<img width="824" height="461" alt="ItatingProcessAccounName" src="https://github.com/user-attachments/assets/aac5d927-99cf-44b4-8244-d9b0bccc15b5" />

```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where FolderPath has_any ("c:\\programdata\\","\\Start\\" ) 
| where FileName contains "revshell.exe"
```


### Flags 21 → 31 — Remote session and attacker activity chronology

**Remote session device name:** 对手

**Remote session IP (session meta):** 100.64.100.6

<img width="824" height="461" alt="ItatingProcessAccounName" src="https://github.com/user-attachments/assets/7effa2b5-4564-446c-9d3e-60d1675c6d64" />
<img width="665" height="168" alt="initiatino Process VersioninfoProductVersion" src="https://github.com/user-attachments/assets/eb01eb23-8a3f-4a8e-b504-29cb5920c9e0" />

```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where FolderPath has_any ("c:\\programdata\\","\\Start\\" ) 
| where FileName contains "revshell.exe"
```

**Internal pivot IP:** 10.168.0.6

<img width="588" height="449" alt="where Devicevane == Ch-ops-wksuZ" src="https://github.com/user-attachments/assets/93df49d1-118c-40fe-94a8-13d5bbb98341" />

```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| distinct InitiatingProcessRemoteSessionIP
```

**First suspicious logon:** 2025-11-23T03:08:31.1849379Z from 104.164.168.17 (geo: Vietnam) using account chadmin

<img width="858" height="493" alt="vwwice somt ents" src="https://github.com/user-attachments/assets/0110b427-69fb-4542-8c14-086d514f2887" />
<img width="747" height="264" alt="Geolocation data from" src="https://github.com/user-attachments/assets/8a99a9e7-e7f3-44a8-b9c1-f39970820eae" />

KQL (logon/process/file correlation):
```
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where ActionType == "LogonSuccess" and LogonType == "Network" and RemoteDeviceName == "对手"
```

**First process after logon:** explorer.exe

<img width="995" height="461" alt="AccounDonir" src="https://github.com/user-attachments/assets/843d3657-53f1-415a-80f0-227677f67c3a" />

```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-24))
| where AccountDomain contains "ch-ops-wks02" and AccountName contains "chadmin" and InitiatingProcessAccountName contains "chadmin"
```

**First file opened:** CH-OPS-WKS02 user-pass.txt

<img width="1024" height="399" alt="Screenshot 2026-01-18 at 2 17 31 PM" src="https://github.com/user-attachments/assets/363a135b-705a-441d-a495-3dacd85fca72" />

```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-24))
| where AccountDomain contains "ch-ops-wks02" and AccountName contains "chadmin" and InitiatingProcessAccountName contains "chadmin"
| where InitiatingProcessId == 5732
| project TimeGenerated, FileName, InitiatingProcessCommandLine, InitiatingProcessId, ProcessCommandLine
```


**Next action after file:** ipconfig.exe

<img width="1063" height="462" alt="Screenshot 2026-01-18 at 2 24 01 PM" src="https://github.com/user-attachments/assets/0f269782-8ab5-4cea-b32a-7a378f9a446c" />

```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-24))
| where AccountDomain contains "ch-ops-wks02" and AccountName contains "chadmin" and InitiatingProcessAccountName contains "chadmin"
| project TimeGenerated, FileName, InitiatingProcessCommandLine, InitiatingProcessId, ProcessCommandLine
```

**Next account used:** ops.maintenance

<img width="748" height="499" alt="where Devicehame wa ch-ops-wk502" src="https://github.com/user-attachments/assets/64568512-168d-487b-b2e6-70521eb3b52f" />

```
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02" 
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-24))
| where RemoteIP contains "104.164.168.17"
| project TimeGenerated, AccountName, ActionType, RemoteIP
```

---
## 🔍 Timeline (selected key events)

| Timestamp (UTC) |	Event |
|----------|-------|
| 2025-11-23T03:08:31.1849379Z	| First suspicious logon (Account: chadmin, RemoteIP: 104.164.168.17)
| 2025-11-23T03:11:00+	| explorer.exe launched under chadmin (initial session activity)
| 2025-11-23T03:46:08.400686Z	| MaintenanceRunner_Distributed.ps1 first outbound beacon attempt
| 2025-11-23T03:47:21.8529749Z	| ConfigAdjust Application event (privilege simulation)
| 2025-11-23T03:46–03:50Z	| Encoded PowerShell executed → Write-Output 'token-6D5E4EE08227'
| 2025-11-23T03:4X	| curl.exe used to download revshell.exe from ngrok URL
| 2025-11-23T03:4X	| revshell.exe written to user profile and executed via explorer.exe
| 2025-11-23T03:5X	| revshell.exe attempts outbound connections to 13.228.171.119:11746
| 2025-11-23T03:5X	| Staging files created: inventory_6ECFD4DF.csv and temp copy
| 2025-11-24 → 2025-11-30	| Scheduled task added, Run key flip-flop observed, AV exclusion attempt
| 2025-11-30T01:03:17.6985973Z	| Latest successful ConnectionSuccess to beacon endpoint
---

## 🧩 MITRE ATT&CK Mapping

| Tactic	| Technique	| Evidence |
|---------|-----------|----------|
| Initial Access / Execution	| T1059.001 | PowerShell:	MaintenanceRunner_Distributed.ps1, -EncodedCommand usage
| Persistence	| T1547.001/T1053 | Registry Run Keys/Scheduled Task	Run key: MaintenanceRunner, scheduled task CorpHealth_A65E64
| Defense Evasion |	T1562.001/T1564 | Log Deletion/EncodedCommand: attempt to set Defender Exclusion, Run-key deleted, event log cleanup patterns
| Credential Access |	T1003/T1552	| CH-OPS-WKS02 user-pass.txt, registry queries, staged inventory data
| Privilege Escalation |	T1134	| Token manipulation: ProcessPrimaryTokenModified (token change), SID modified
| Lateral Movement |	T1021	| Remote sessions: schtasks style pivoting metadata
| Exfiltration |	T1041/T1105	| Staged CSVs, ngrok-assisted tunnel, remote C2 IPs and external downloads
| Command & Control	| T1071/T1105	| Reverse shell: revshell.exe connecting to 13.228.171.119:11746 via tunnel
---


## 🔑 Indicators of Compromise (IoCs) 

### Hosts & Accounts

***Host:*** ch-ops-wks02

***Accounts:*** chadmin, ops.maintenance

***Remote session device name:*** 对手

***Remote IPs:*** 104.164.168.17, 100.64.100.6, internal 10.168.0.6

### Files & Paths:

- C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv

- C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv

- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe

- MaintenanceRunner_Distributed.ps1

### Hashes

***SHA256:*** 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

### Network

- Beacon (found in logs): 127.0.0.1:8080 (script-level)

- Download URL: https[:]//unresuscitating-donnette-smothery[.]ngrok-free[.]dev/revshell[.]exe

- C2 / reverse shell endpoint: 13.228.171.119:11746

### Registry

- HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent

- Scheduled Task tree: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64

- Run value name: MaintenanceRunner (created -> deleted)

---

## 🛡 Custom Detection Rule Ideas

Alert on MaintenanceRunner script activity outside approved schedule
```
DeviceProcessEvents
| where ProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| where Timestamp notbetween (/* approved schedule windows */)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```
Curl.exe used to download .exe from external tunnels
```
DeviceProcessEvents
| where FileName == "curl.exe" and ProcessCommandLine contains "ngrok"
| project TimeGenerated, DeviceName, ProcessCommandLine, RemoteUrl

```
Writes to CorpHealth diagnostics followed by immediate network egress
```
DeviceFileEvents
| where FolderPath has @"\CorpHealth\" and ActionType == "FileCreated"
| join kind=inner (
  DeviceNetworkEvents
  | where Timestamp between (ago(1h) .. now())
) on DeviceId
| project DeviceName, FileName, FolderPath, TimeGenerated

```
Token modification events
```
DeviceEvents
| where AdditionalFields has_any ("tokenChangeDescription","Privileges were added")
| project TimeGenerated, DeviceName, InitiatingProcessId, AdditionalFields

```
Startup folder or ProgramData writes of new executables
```
DeviceFileEvents
| where FileName endswith ".exe"
| where FolderPath has_any ("C:\\ProgramData\\Microsoft\\Windows\\Start, "\\StartUp")
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
```
---

## 🧭 Remediation & Containment Checklist

***Immediate Containment*** 

Isolate ch-ops-wks02 from network (maintain EDR connectivity if possible).

Collect full EDR artifacts: process trees, file copies, registry dumps, network logs, DeviceEvents JSON.

***Credentials***

Rotate chadmin, ops.maintenance, and any service account credentials accessible by these accounts.

Force password changes and revoke active sessions. Require MFA for admin/ops accounts.

***Block & Mitigate***

Block 13.228.171.119 and the entire ngrok tunnel domain at perimeter/proxy and IDS/IPS.

Block outbound port 11746 or alert on it.

***Remove Persistence***

After evidence capture, remove scheduled task CorpHealth_A65E64, delete Run key entries, and remove revshell.exe from Startup and user profile.

Quarantine and submit revshell.exe and any staged CSVs for malware analysis.

***Hunt & Scope***

Hunt for MaintenanceRunner_Distributed.ps1, inventory_* files, revshell.exe, and the SHA256 across estate.

Investigate pivot host 10.168.0.6 and remote session IPs 100.64.100.6 and 104.164.168.17 for broader compromise.

***Hardening***

Enforce automation-only constraints for operational accounts: disable interactive logons, require managed identities or constrained credentials, and use just-in-time escalation.

Review and tighten Defender exclusion policy; alert on Add-MpPreference/Set-MpPreference events.

Implement egress filtering and tunneling detection (block common ngrok/temporary-tunnel patterns).

***Recovery***

Reimage affected host(s) after artifacts collected, unless forensic policy dictates alternatives.

Rebuild and redeploy CorpHealth agent binaries from known-good sources.

***Post-Incident***

Conduct root-cause review, update playbooks, and present findings to leadership for escalation and potential external reporting.

---

## 💡 Lessons Learned

- Automation accounts must be constrained. Allowing administrative automation accounts to log on interactively materially increases risk.

- Baseline scheduled/script behavior. Monitor scripts that run outside documented schedules — an early high-signal detector.

- Watch living-off-the-land download patterns. curl.exe, bitsadmin, powershell -EncodedCommand from non-system contexts are high-value detection points.

- Staging in diagnostic folders is a tell. Attackers hide in legitimate maintenance paths — monitor those folders for unusual file creation and egress correlation.

- Rapid pivoting & token modification are high risk. Token-change events combined with credential file access should escalate to IR immediately.

- Temporary tunneling platforms (ngrok, etc.) are commonly abused. Egress detection and domain blocking can disrupt C2 and tooling delivery.

---

## ✅ Final Recommendation

  Treat this as an active threat/assume breach. Escalate to full incident response: collect and preserve forensic evidence, rotate credentials, hunt for related artifacts across the estate, and harden operational account practices to prevent recurrence.
