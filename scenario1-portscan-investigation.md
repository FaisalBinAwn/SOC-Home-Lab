# Scenario 1 — Port Scan Detection Investigation

## Overview

This investigation documents the detection and analysis of a network reconnaissance attack performed from the Kali Linux attacker machine against the Windows victim endpoint within the SOC Home Lab environment.

The objective was to validate Elastic SIEM visibility, alert generation, and SOC analyst investigation procedures for detecting port scanning activity.

---

## Alert Information

| Field          | Value                                  |
| -------------- | -------------------------------------- |
| Alert Name     | Potential SYN-Based Port Scan Detected |
| Date/Time      | Jun 20, 2026 @ 09:25:00.847            |
| Severity       | Low                                    |
| Source IP      | 10.0.0.5                               |
| Destination IP | 10.0.0.4                               |

---

## Attack Description

A full TCP port scan was launched from the Kali Linux attacker machine against the Windows victim endpoint using Nmap.

The objective of the attack was to identify exposed services that could potentially be targeted during later stages of an intrusion.

Elastic SIEM collected Windows Filtering Platform (WFP) packet drop events and generated an alert based on abnormal connection activity.

---

## What I Found in the Logs

Investigation revealed that source host **10.0.0.5** performed active reconnaissance against **10.0.0.4** by scanning all TCP ports.

The scan successfully identified the following open ports:

| Port | Service                 |
| ---- | ----------------------- |
| 135  | RPC Endpoint Mapper     |
| 139  | NetBIOS Session Service |
| 445  | SMB                     |

The scan pattern matched typical Nmap TCP Connect Scan behavior.

### Evidence — Nmap Scan Results

![Nmap Scan Output] 
<img width="694" height="405" alt="SS11" src="https://github.com/user-attachments/assets/865164cc-dba7-4af4-a717-7104705c8f11" />

---

### Evidence — Event Volume Spike

Elastic Discover showed a significant spike of Windows Security Event ID **5152** events generated during the scan activity.

A total of approximately **135,048 packet drop events** were recorded during the attack window, confirming large-scale reconnaissance behavior.

![Discover View]
<img width="800" alt="SS14" src="https://github.com/user-attachments/assets/0a84811d-cb52-40c5-a61a-9b987d45717e" />

---

## True Positive or False Positive

**Classification:** True Positive (TP)

### Why?

The alert accurately identified malicious reconnaissance activity.

Although port scanning by itself is considered low severity, the activity originated from an internal host within the environment. This indicates that an attacker already has network access and may attempt follow-up exploitation against discovered services.

### Evidence — Detection Alert Generated

The custom Elastic Security detection rule successfully generated an alert based on the excessive number of packet drop events.

![Elastic Alert]
<img width="800" alt="SS17" src="https://github.com/user-attachments/assets/ee3269a0-9308-4ed3-a882-a199271f6f4a" />

---

## Alert Details

Further investigation of the alert showed:

* Source IP: 10.0.0.5
* Destination IP: 10.0.0.4
* Total Events: 131,060
* Detection Rule: Potential SYN-Based Port Scan Detected

The alert metadata confirmed that the event volume exceeded the configured threshold and was consistent with automated scanning activity.

![Alert Details]
<img width="1920" height="927" alt="SS13" src="https://github.com/user-attachments/assets/b4647d91-272d-4137-b00e-707637a23c74" />

---

## Indicators of Compromise (IOCs)

| IOC Type       | Value         |
| -------------- | ------------- |
| Source IP      | 10.0.0.5      |
| Destination IP | 10.0.0.4      |
| Tool Used      | Nmap          |
| Open Ports     | 135, 139, 445 |

---

## MITRE ATT&CK Mapping

| Tactic                  | Technique                         |
| ----------------------- | --------------------------------- |
| TA0043 – Reconnaissance | T1595 – Active Scanning           |
| TA0007 – Discovery      | T1046 – Network Service Discovery |

---

## Actions Taken

* Identified source host 10.0.0.5 as the scanning system.
* Investigated exposed services discovered during the scan.
* Monitored ports 135, 139, and 445 for follow-up activity.
* Escalated findings for additional analysis.
* Recommended blocking the scanning host at the network firewall.

---

## Lessons Learned

* Elastic SIEM successfully detected large-scale reconnaissance activity.
* Event ID 5152 provides excellent visibility into network scanning behavior.
* Threshold-based detection rules are effective for identifying port scans.
* Internal reconnaissance activity should always be investigated due to the risk of lateral movement and exploitation.

---

## Conclusion

A full Nmap TCP port scan originating from the Kali Linux attacker machine was successfully detected and investigated using Elastic SIEM.

The attack generated over 131,000 security events, identified multiple exposed services on the target host, and triggered a custom detection rule designed to identify scanning activity.

The incident was classified as a True Positive and mapped to MITRE ATT&CK techniques T1595 (Active Scanning) and T1046 (Network Service Discovery), demonstrating the effectiveness of the SOC Home Lab for detection engineering and incident investigation practice.
