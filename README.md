# 🛡️ Open Threat Research for a Small‑Business Network (HightechLab.com)

Network Security is vital in today's digital landscape due to the increasing reliance on intercinnected systems for various business operations. Businesses depend on network for data storage, communication, and transactions, making them prime taegets for ayber attacks. Cyber threats continuously evolve, posing risks such as data breaches, financial losses, and opertional disruptions.

---

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture1.png" width="450" alt="imag5">
</p>

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Objectives](#3-objectives)
4. [Approach](#4-approach)
5. [Results](#5-results)
6. [Evaluation of the Results](#6-evaluation-of-the-results)
7. [Conclusion](#7-conclusion)
8. [References](#8-references)

---

## 1. Abstract

In today’s digital landscape, building **secure and efficient networks** is imperative for the seamless operation of businesses. This project explores network setup and defence, focusing on a lab network called **HightechLab.com** (six Windows hosts + PfSense) and a separate **Internet** network (Kali Linux adversary host).

The study:

* Designs & configures the entire virtual infrastructure in **VirtualBox 7.1.14**.
* Hardens systems with **Group Policy Objects (GPOs)**, **Sysmon**, and other controls.
* Simulates threats (OS credential dumping / LSASS) to gauge resilience.

Despite hurdles—e.g., DHCP mis‑scopes and firewall blocks—the project delivers actionable guidance for small businesses seeking enterprise‑grade security.

---

## 2. Introduction

Small companies often struggle to match enterprise security budgets. By virtualising everything, we replicate a realistic SMB environment and walk through each configuration step.

* **HightechLab.com (192.168.1.0/24)** – Business LAN: 1× Windows Server 2022 (AD DS/DHCP/DNS) + 4× Windows 10 clients + PfSense LAN side.
* **Internet (10.0.5.0/24)** – Host‑only “ISP” network: Kali Linux adversary + PfSense WAN side.
  
<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture16.png" width="450" alt="imag5">
</p>


Key takeaway: stronger baselines + instrumented logging = faster threat detection and mitigation.

---

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture2.png" width="450" alt="imag5">
</p>

---

## 3. Objectives

### 3.1 Network Configuration

* Configure NAT & DHCP (`VBoxManage`) and set up PfSense dual interfaces for secure routing.

### 3.2 System Deployment & Configuration

* **Kali Linux** (adversary).
* **Windows Server 2022** promoted to DC.
* **Windows 10** clients joined to OUs.

### 3.3 Security Enhancement

* Create GPOs (Windows Update, Defender, advanced audit & logging).
* Install **Sysmon** to extend visibility.

### 3.4 Threat Simulation & Mitigation

* Reproduce **OS Credential Dumping – LSASS**.
* Document findings, build counter‑measures.

---

## 4. Approach

### 4.1 Configure Network Adapter, NAT & DHCP

```bash
# Create NAT network HightechLab.com
VBoxManage natnetwork add \
  --netname HightechLab.com --network "192.168.1.0/24" --enable --dhcp on
# DHCP fine‑tuning (Internet network)
VBoxManage dhcpserver add \
  --netname Internet \
  --ip 10.0.5.1 --netmask 255.255.255.0 \
  --lowerip 10.0.5.10 --upperip 10.0.5.50 --enable
```

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture3.png" width="450" alt="imag5">
<img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture4.png" width="450" alt="imag6">
</p>

---

### 4.2 PfSense Router

* Two NICs: **LAN** 192.168.1.1/24, **WAN** 10.0.5.5/24.
* Corrected an IP mismatch via console (`set interfaces IP address`).

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture5.png" width="450" alt="imag5">
</p>

### 4.3 Kali Linux (Adversary)

* Connected to **Internet** network, got DHCP 10.0.5.11.
* Verified ICMP path to PfSense.

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture6.png" width="450" alt="imag5">
</p>

### 4.4 Windows Server 2022 (Domain Controller)

Steps

1. Assign static IP 192.168.1.5/24 & DNS = self.
2. Install roles **AD DS**, **DHCP**, **DNS** via Server Manager.
3. Promote to forest root `HightechLab.com`.
4. Create DHCP scope 192.168.1.40‑60.

---

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture7.png" width="450" alt="imag5">
<img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture8.png" width="450" alt="imag6">
</p>

---

#### 4.4.2 Organisation Units & Users

* OUs: *Information Technology*, *Marketing*, *Production*, *Accounting*.
* Users: Meredith Grey (admin), Derek Shepherd, Cristina Yang, Mark Sloan.

#### 4.4.3 Windows 10 VMs

* Names: IT01, MKT02, PRD03, ACCT04.
* Domain‑joined & moved to their OUs.

---

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture9.png" width="450" alt="imag5">
</p>

---
### 4.5 Group Policy Objects

* **Windows Update Services** – disable auto download (research scenario).
* **Security Settings** – relax Defender & SmartScreen.
* **Advanced Audit + Event Log size** – maximise retention.

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture10.png" width="450" alt="imag5">
</p>

### 4.6 Sysmon Installation

```powershell
Sysmon64.exe -accepteula -i sysmon\sysmon-config.xml
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:2147483647
```

<p float="center">
   <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture11.png" width="450" alt="imag5">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture12.png" width="450" alt="imag6">
</p>

### 4.7 Threat Simulation – LSASS Dumping

MITRE ATT\&CK chain:

* **TA0042** Resource Development → T1587.001 / T1608.001.
* **TA0002** Execution → T1204.002.
* **TA0007** Discovery → T1082, T1033, T1057.
* **TA0004** Priv‑Esc → T1134.001.
* **TA0005** Defence Evasion → T1055.002.
* **TA0006** Credential Access → **T1003.001**.

### 4.8 Execution Steps

1. **Kali:** Generate payload `payload.exe` with `msfvenom`, serve over Python HTTP.
2. **Metasploit:** Configure handler (`multi/handler` LHOST 10.0.5.11 LPORT 8080).
3. **Victim (MKT02):** Download & run payload as admin (after lowering IE security).
4. **PfSense** initially blocked outbound ; policy adjusted to allow test.

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture13.png" width="450" alt="imag5">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture14.png" width="450" alt="imag6">
</p>

---

## 5. Results

### 5.1 Network Configuration

* NAT + DHCP functional; clients receive correct leases.

### 5.2 PfSense Router

* Dual‑homed routing verified with ICMP & HTTP tests.

### 5.3 System Deployment

* AD, DHCP, DNS all operational; OUs & users created.

### 5.4 Security Enhancement

* GPOs applied across all clients; Sysmon logging extended.

### 5.5 Threat Simulation & Mitigation

* LSASS dump **succeeded** when firewall outbound was open, producing Sysmon ID 10 + Security ID 4688 logs.
* When rule restored, reverse shell blocked—attack contained.

<p float="center">
  <img src="https://github.com/poohb0321/Open_Threat_Research_for_a_small_business_network/blob/db2c8f880e3078697c3515ea5d12ead6cb3e0c56/images/Picture15.png" width="450" alt="imag5">
</p>

---

## 6. Evaluation of the Results

* **Adherence** – all objectives met (network build, hardening, attack simulation).
* **Security Effectiveness** – GPO baseline + Sysmon provided high‑fidelity logs.
* **Impact** – Demonstrated layered defence: PfSense + host logs = detection & containment.

---

## 7. Conclusion

This open‑threat research illustrates how an SMB can achieve enterprise‑style security monitoring **entirely in a virtual lab**. With thorough baseline hardening and visibility, even sophisticated attacks (LSASS dump) can be detected and thwarted.

---

## 8. References

1. Oracle VirtualBox NAT Networking – [https://docs.oracle.com/virtualbox](https://docs.oracle.com/virtualbox)
2. PfSense – [https://www.pfsense.org](https://www.pfsense.org)
3. Kali Linux – [https://www.kali.org](https://www.kali.org)
4. Windows Server 2022 – [https://microsoft.com/windows-server](https://microsoft.com/windows-server)
5. AD DS – [https://learn.microsoft.com/.../active-directory-domain-services-overview](https://learn.microsoft.com/.../active-directory-domain-services-overview)
6. DHCP – [https://learn.microsoft.com/.../dhcp-top](https://learn.microsoft.com/.../dhcp-top)
7. DNS – [https://www.cloudflare.com/learning/dns/what-is-dns](https://www.cloudflare.com/learning/dns/what-is-dns)
8. Active Directory Security Groups – [https://learn.microsoft.com/.../understand-security-groups](https://learn.microsoft.com/.../understand-security-groups)
9. Group Policy – [https://learn.microsoft.com/.../waas-wufb-group-policy](https://learn.microsoft.com/.../waas-wufb-group-policy)
10. Windows Auth GP Settings – [https://learn.microsoft.com/.../group-policy-settings-used-in-windows-authentication](https://learn.microsoft.com/.../group-policy-settings-used-in-windows-authentication)
11. Sysmon – [https://learn.microsoft.com/sysinternals/downloads/sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
12. MITRE ATT\&CK T1003.001 – [https://attack.mitre.org/techniques/T1003/001](https://attack.mitre.org/techniques/T1003/001)

---
