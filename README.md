# SOC Home Lab — Elastic SIEM

A hands-on home lab built to simulate real attacks, detect them 
using Elastic SIEM, and practice SOC analyst workflows including 
alert triage and incident investigation.

## Lab Architecture

| VM | Role | IP |
|---|---|---|
| Ubuntu 22.04 | Elasticsearch + Kibana + Fleet Server | 10.0.0.3 |
| Windows 10 | Victim endpoint — Sysmon + Elastic Agent | 10.0.0.4 |
| Kali Linux | Attacker machine | 10.0.0.5 |

<img width="900" alt="SS7" src="https://github.com/user-attachments/assets/1ab9ba70-7e4b-4377-80a2-0777684404ea" />

## Tools & Stack
- Elastic SIEM 8.19.16
- Sysmon with custom config
- Elastic Agent + Fleet Server
- Kali Linux (Nmap, Hydra, Metasploit)
- MITRE ATT&CK Framework
- NCA ECC / SAMA CSF alignment

## Certifications
- CompTIA Security+
- CompTIA CySA+
- EC-Council CSA
- eLearnSecurity eCTHP
- NCA CyberPro+

## Attack Scenarios

| # | Scenario | Tool | Detection | Status |
|---|---|---|---|---|
| 1 | Network Port Scan | Nmap | EID 5152 + Threshold Rule | ✅ Complete |
| 2 | RDP Brute Force | Hydra | EID 4625 | 🔄 In Progress |
| 3 | LSASS Dump | Mimikatz | EID 10 | ⏳ Planned |
| 4 | Ransomware Sim | PowerShell | EID 11 | ⏳ Planned |
| 5 | C2 Beaconing | Metasploit | EID 3 | ⏳ Planned |

<img width="900" alt="SS9" src="https://github.com/user-attachments/assets/213d1142-7b52-4770-8509-d8bb62dad343" />


## Investigation Reports
- [Scenario 1 — Port Scan Detection](scenario1-portscan-investigation.md)
