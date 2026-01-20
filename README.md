# Threat Hunt Report: CorpHealth — Traceback

***Analyst:*** Christopher Jimenez

***Date Completed:*** 2026-01-18

***Environment Investigated:*** ch-ops-wks02 (with pivots to internal host 10.168.0.6)

***Timeframe:*** Mid-November – Early December 2025 (key activity 2025-11-23 → 2025-11-30)

---

## 🧠 Scenario Overview


CorpHealth is a lightweight operations platform used for endpoint stability, post-patch health checks, and diagnostics. It runs scheduled scripts and background services under a dedicated operational account intended for automation only.
During a mid-November maintenance window a single workstation (ch-ops-wks02) produced a cluster of events that superficially resembled maintenance, but occurred outside normal windows, deviated from baselines, and included manual script launches, outbound beaconing, file staging in diagnostic folders, registry modifications, and the download/execution of an unsigned reverse shell. This investigation reconstructs the timeline and determines whether activity is authorized automation or misuse/compromise.

---

## 🎯 Executive Summary

The investigation discovered ch-ops-wks02 exhibited multi-stage suspicious behavior during an off-hours window in late November 2025:

A unique maintenance script (MaintenanceRunner_Distributed.ps1) ran outside of approved automation and attempted outbound beaconing.
The script successfully connected (handshake) to a beacon endpoint; soon after, staged diagnostic exports were created in CorpHealth folders and temporary user locations.

Registry artifacts and a scheduled task (nonstandard) were created; a short-lived Run-key value was added then removed.
A token modification (privilege simulation) and a PowerShell -EncodedCommand were observed.
The host used curl.exe to fetch revshell.exe from an ngrok tunnel, executed it via explorer.exe, and copied it into the Startup folder for persistence.
Remote session metadata shows a remote session device label 对手 and remote IPs including 104.164.168.17 (initial login origin; geolocated to Vietnam), 100.64.100.6 (remote session IP), and an internal pivot host 10.168.0.6.
The activity chain indicates hands-on-keyboard behavior initiating from a remote session, credential use/harvesting, staging for exfiltration, and a remote foothold via a reverse shell.

Conclusion: The observed behavior is consistent with misuse of privileged automation and active malicious activity (credential harvesting, staging, ingress of a reverse shell, persistence). This is beyond benign automation and should be escalated to incident response.


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

KQL:

``` 
DeviceLogonEvents
| where DeviceName startswith "ch-"
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| project AccountName, DeviceName, TimeGenerated
```
### Flag 1 — Unique maintenance file

**Objective:** Find script unique to this host — MaintenanceRunner_Distributed.ps1.

KQL:

```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-10) .. datetime(2025-12-05))
| where FileName endswith ".ps1"
| project Timestamp, FolderPath, FileName, InitiatingProcessCommandLine
```

### Flag 2 → 4 — Beaconing behavior (first attempt & success)

**First outbound beacon:** 2025-11-23T03:46:08.400686Z.

**Beacon destination:** 127.0.0.1:8080.

**Successful connection (latest):** 2025-11-30T01:03:17.6985973Z.

KQL (network pivot):
```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner"
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessCommandLine
```
### Flag 5 → 7 — Staging artifacts and their integrity

**Primary staged file:** C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv

**SHA-256:** 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

**Duplicate/working copy:** C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv

KQL (file find + hash):
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FolderPath has @"\CorpHealth\" or FolderPath has @"\Diagnostics\"
| project Timestamp, FolderPath, FileName, SHA256, InitiatingProcessCommandLine
```
### Flag 8 → 10 — Registry & scheduled-task persistence

**Suspicious registry key:** HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent

**Scheduled Task created:** HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64

**Run value name (ephemeral):** MaintenanceRunner (created then deleted)

KQL (registry):
```
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType in ("RegistryKeyCreated","RegistryValueSet","RegistryKeyDeleted")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
```
### Flag 11 → 15 — Privilege simulation & token modification

**ConfigAdjust Application event (first):** 2025-11-23T03:47:21.8529749Z

**Encoded PowerShell decoded:** Write-Output 'token-6D5E4EE08227'

**InitiatingProcessId for PrimaryTokenModified:** 4888

**OriginalTokenUserSid:** S-1-5-21-1605642021-30596605-784192815-1000

KQL (token change):
```
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where AdditionalFields has_any ("tokenChangeDescription","Privileges were added")
| project TimeGenerated, InitiatingProcessId, AdditionalFields, InitiatingProcessCommandLine
```
KQL (decode EncodedCommand):
```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine contains "-EncodedCommand"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| project TimeGenerated, FileName, Decoded, ProcessCommandLine
```
### Flag 12 — AV exclusion attempt

**Attempted exclusion path:** C:\ProgramData\Corp\Ops\staging

KQL (Defender prefs):
```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine has_any ("Set-MpPreference","Add-MpPreference","-ExclusionPath")
| project TimeGenerated, FileName, ProcessCommandLine
```
### Flag 16 → 20 — Ingress of reverse shell & persistence

**Downloaded filename:** revshell.exe

**Download URL:** https[:]//unresuscitating-donnette-smothery[.]ngrok-free[.]dev/revshell[.]exe

**Executed by:** explorer.exe

**External IP contacted by binary:** 13.228.171.119 (port 11746)

**Startup path (persistence):** C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe

KQL (download & execution):
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FileName endswith ".exe" and FolderPath has_any(@"C:\Users\", "Start Menu", "ProgramData")
| project TimeGenerated, FolderPath, FileName, InitiatingProcessCommandLine, RemoteUrl
```
KQL (network from revshell):
```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "revshell"
| where RemotePort == 11746
| project TimeGenerated, RemoteIP, RemotePort, ActionType
```
### Flags 21 → 31 — Remote session and attacker activity chronology

**Remote session device name:** 对手

**Remote session IP (session meta):** 100.64.100.6

**Internal pivot IP:** 10.168.0.6

**First suspicious logon:** 2025-11-23T03:08:31.1849379Z from 104.164.168.17 (geo: Vietnam) using account chadmin

**First process after logon:** explorer.exe

**First file opened:** CH-OPS-WKS02 user-pass.txt

**Next action after file:** ipconfig.exe

**Next account used:** ops.maintenance

KQL (logon/process/file correlation):
```
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-22) .. datetime(2025-11-24))
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, RemoteDeviceName
```
```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where AccountName in ("chadmin","ops.maintenance")
| where Timestamp between (datetime(2025-11-23) .. datetime(2025-11-24))
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
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
| Initial Access / Execution	| T1059.001 | PowerShell	MaintenanceRunner_Distributed.ps1, -EncodedCommand usage
| Persistence	| T1547.001 | Registry Run Keys, T1053 Scheduled Task	Run key MaintenanceRunner, scheduled task CorpHealth_A65E64
| Defense Evasion |	T1562.001/ScriptBlock Evasion, T1564 | Log Deletion	EncodedCommand, attempt to set Defender Exclusion, Run-key deleted, event log cleanup patterns
| Credential Access |	T1003 / T1552? (Harvesting)	| CH-OPS-WKS02 user-pass.txt, registry queries, staged inventory data
| Privilege Escalation |	T1134 / Token manipulation	| ProcessPrimaryTokenModified (token change), SID modified
| Lateral Movement |	T1021 (Remote Services)	| Remote sessions; schtasks style pivoting metadata
| Exfiltration |	T1041 / T1105	| Staged CSVs, ngrok-assisted tunnel, remote C2 IPs and external downloads
| Command & Control	| T1071 / T1105	| Reverse shell revshell.exe connecting to 13.228.171.119:11746 via tunnel
---


## 🔑 IOCs

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

## 🛡 Detection ideas & KQL rules

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
Writes to CorpHealth diagnostics followed by immediate network egress
```
```
DeviceFileEvents
| where FolderPath has @"\CorpHealth\" and ActionType == "FileCreated"
| join kind=inner (
  DeviceNetworkEvents
  | where Timestamp between (ago(1h) .. now())
) on DeviceId
| project DeviceName, FileName, FolderPath, TimeGenerated
Token modification events
```
```
DeviceEvents
| where AdditionalFields has_any ("tokenChangeDescription","Privileges were added")
| project TimeGenerated, DeviceName, InitiatingProcessId, AdditionalFields
Startup folder or ProgramData writes of new executables
```
```
DeviceFileEvents
| where FileName endswith ".exe"
| where FolderPath has_any(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "StartUp")
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
