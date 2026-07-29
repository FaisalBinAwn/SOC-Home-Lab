# Scenario 3 — LSASS Memory Access Detection Investigation

## Overview

This investigation documents the detection and analysis of an OS credential dumping attack performed on the Windows victim endpoint within the SOC Home Lab environment.

The objective was to validate Elastic SIEM visibility, Sysmon Event ID 10 (ProcessAccess) logging, alert generation, and SOC analyst investigation procedures for detecting LSASS memory access attempts using Mimikatz.

---

## Alert Information

| Field | Value |
| --- | --- |
| Alert Name | LSASS Memory Access - Potential Credential Dumping |
| Date/Time | Jul 28, 2026 @ 17:35:48.113 |
| Severity | Critical |
| Source Host | 10.0.0.4 |
| Destination IP | 10.0.0.4 |

---

## Attack Description

A credential dumping attack was executed on the Windows victim endpoint using Mimikatz (`mimikatz.exe`) targeting the Local Security Authority Subsystem Service (`lsass.exe`) process memory.

The objective of the attack was to extract sensitive authentication data, including NTLM password hashes and Kerberos tickets, directly from LSASS process memory.

Elastic SIEM collected Sysmon Event ID 10 (Process Access) events and generated a Critical-severity alert based on suspicious process access rights requested against `lsass.exe`.

---

## What I Found in the Logs

Investigation revealed that source process **`C:\mimikatz\x64\mimikatz.exe`** accessed the memory space of target process **`C:\Windows\System32\lsass.exe`** on host **10.0.0.4**.

The event details showed a GrantedAccess mask of **`0x1010`**, which corresponds to `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION` rights—commonly leveraged by memory dumping utilities.

The following process was targeted during the attack:

| Target Process | Service / Component |
| --- | --- |
| `lsass.exe` | Local Security Authority Subsystem Service |

The attack pattern showed direct process memory access targeting administrative credentials, enabling potential privilege escalation and lateral movement.

### Evidence — Mimikatz Execution
<img width="979" height="328" alt="ss5" src="https://github.com/user-attachments/assets/74f87915-a85f-4cfa-a23a-bf338bfce4d0" />
<img width="970" height="490" alt="ss6" src="https://github.com/user-attachments/assets/e89a99cf-7a3c-4876-a377-b4825677f66b" />
<img width="979" height="511" alt="ss7" src="https://github.com/user-attachments/assets/be4eeb8d-bb89-4d55-9794-07f2ebe055c9" />

---

### Evidence — Event Volume in Elastic Discover

Elastic Discover showed documents for Sysmon Event ID **10** generated during the attack window.

<img width="1617" height="330" alt="ss1" src="https://github.com/user-attachments/assets/c2902d24-72d3-465f-b9a6-1c6aef7335f9" />
<img width="775" height="649" alt="ss2" src="https://github.com/user-attachments/assets/8196c5a5-921e-40ea-9e4e-5962ee4209cc" />

---

## True Positive or False Positive

**Classification:** True Positive (TP)

### Why?

Credential dumping is a critical-severity attack technique. The attacker specifically targeted `lsass.exe` using Mimikatz to extract stored credentials and hashes from memory. The GrantedAccess value (`0x1010`) confirms direct memory read permissions were requested, which is non-standard behavior for legitimate applications and indicates malicious credential theft activity.

### Evidence — Detection Alert Generated

<img width="1667" height="724" alt="ss3" src="https://github.com/user-attachments/assets/9dff1559-7e6c-4ce2-b944-e2735fa9cb3e" />
<img width="737" height="570" alt="ss4" src="https://github.com/user-attachments/assets/447fd0eb-0ef0-4be5-9ba3-3d623ce0c6ad" />

The custom Elastic Security detection rule successfully generated a Critical severity alert based on the suspicious process access rights against LSASS.

---

## Alert Details

Further investigation of the alert showed:

* Source Host: 10.0.0.4
* Source Process: `C:\mimikatz\x64\mimikatz.exe`
* Target Process: `C:\Windows\System32\lsass.exe`
* Targeted Account: `WINDOWS-VICTIM\victim`
* GrantedAccess: `0x1010`
* Detection Rule: LSASS Memory Access - Potential Credential Dumping
The alert metadata confirmed the process access mask matched known credential dumping signatures.

---

## Indicators of Compromise (IOCs)

| IOC Type | Value |
| --- | --- |
| Host IP | 10.0.0.4 |
| Tool Used | Mimikatz |
| Source Process | `C:\mimikatz\x64\mimikatz.exe` |
| Target Process | `C:\Windows\System32\lsass.exe` |
| Targeted Account | `WINDOWS-VICTIM\victim` |
| GrantedAccess Mask | `0x1010` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
| --- | --- |
| TA0006 – Credential Access | T1003 – OS Credential Dumping |
| TA0006 – Credential Access | T1003.001 – LSASS Memory |

---

## Actions Taken

* Locked the compromised user account (`WINDOWS-VICTIM\victim`).
* Isolated host 10.0.0.4 from the network to prevent potential lateral movement.
* Reset the affected user account password.
* Reset the Domain `KRBTGT` account password twice to invalidate potential forged Kerberos tickets.
* Initiated a full scope investigation to check for secondary persistence or compromised hosts.

---

## Lessons Learned

* Sysmon Event ID 10 (ProcessAccess) must be configured in Sysmon XML rules to capture LSASS access events.
* Monitoring specific `GrantedAccess` masks (e.g., `0x1010`, `0x1410`) helps filter legitimate system calls from malicious memory read attempts.
* Enabling LSA Protection (`RunAsPPL`) on Windows endpoints prevents unauthorized processes from reading LSASS memory directly.

---

## Conclusion

An OS credential dumping attack targeting `lsass.exe` via Mimikatz on host 10.0.0.4 was successfully detected and investigated using Elastic SIEM and Sysmon.

The attack generated Sysmon Event ID 10 events with a GrantedAccess mask of `0x1010` and triggered a Critical severity alert. The incident was classified as a True Positive and mapped to MITRE ATT&CK techniques T1003 (OS Credential Dumping) and T1003.001 (LSASS Memory), proving the efficacy of endpoint process monitoring within the SOC Home Lab.

---

## Previous in this series
⬅ [Scenario 2 — SMB Brute Force Detection Investigation](scenario2%20-%20SMB%20Brute%20Force%20Detection%20Investigation.md)
