# 🛡️ Brute Force Detection & Response Lab (Azure Sentinel + Microsoft Defender)


## 🔎 Scenario Overview

As a security analyst in a cloud-first enterprise environment, I observed multiple failed logon attempts targeting several Azure-based virtual machines. These events indicated a potential brute-force campaign from **7 distinct public IPs**.

---

## 🎯 Objective

Detect, contain, and respond to brute-force attempts across Azure-hosted Windows and Linux VMs, in alignment with **NIST 800-61** and **MITRE ATT\&CK** techniques:

* **T1110 – Brute Force**
* **T1078 – Valid Accounts**

---

## 🛠️ Platforms & Tools

* Microsoft Sentinel
* Microsoft Defender for Endpoint (MDE)
* Azure NSGs
* Kusto Query Language (KQL)
* Azure Virtual Machines (Windows/Linux)

---

## 📊 Detection Query (KQL)

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

📍 **Follow-up Verification**
Checked for successful logins from brute-force IPs:

```kql
DeviceLogonEvents
| where RemoteIP in ("212.84.174.78", "92.53.90.243", "92.53.90.248", "149.50.96.98", "193.37.69.105", "103.215.221.225", "59.36.137.172")
| where ActionType == "LogonSuccess"
```

✅ **Result:** No successful logons from attacker IPs.

---

## 🧐 Analysis Summary

| VM Name                                   | IP Address      | Failed Attempts |
| ----------------------------------------- | --------------- | --------------- |
| `winwin10`                                | 212.84.174.78   | 34              |
| `jeff-lab-win-vm`                         | 92.53.90.243    | 11              |
| `jeff-lab-win-vm`                         | 92.53.90.248    | 10              |
| `jeff-lab-win-vm`                         | 149.50.96.98    | 27              |
| `saleh-mde-lab`                           | 193.37.69.105   | 64              |
| `linux-vmtest.p2zfvso05mlezjev3ck4vqd3kd` | 103.215.221.225 | 13              |
| `linux-vmtest.p2zfvso05mlezjev3ck4vqd3kd` | 59.36.137.172   | 21              |

---

## 🧰 Incident Response Steps

### 1️⃣ Preparation

* Logging and monitoring already enabled in **Microsoft Defender for Endpoint**
* Alert thresholds in Sentinel defined for failed login detection
* NSG defaults previously open to internet — security baseline reviewed

---

### 2️⃣ Detection & Triage

* Alert triggered based on brute-force detection query
* Confirmed logon failures from multiple public IPs
* Validated no successful access from attacker IPs
* Prioritized devices based on volume of login attempts

---

### 3️⃣ Containment

* ✅ **All 7 VMs isolated** via MDE
* ✅ **Antimalware scans** executed on each isolated device
* ✅ **NSG modified** to restrict RDP to home IP address only
* ⛔️ Public access blocked on all relevant ports
* 📄 Internal policy proposed requiring RDP restriction by default

---

### 4️⃣ Eradication & Recovery

* Verified VM integrity via Defender scan logs
* Restored access after isolation confirmed no compromise
* Reset credentials for all admin-level accounts on affected machines
* Reviewed and enforced VM baseline security templates

---

### 5️⃣ Lessons Learned & Recommendations

✅ **Key Takeaways:**

* Brute-force attempt detected early thanks to Sentinel KQL rules
* Isolation and containment prevented compromise
* Logging and EDR visibility crucial in verifying system integrity

📌 **Recommended Improvements:**

* Implement Conditional Access Policies
* Enforce Just-In-Time (JIT) VM access
* Require MFA and long passphrases for all VM users
* Geo-block known hostile regions for RDP

---

## ⚙️ MITRE ATT\&CK Mapping

| Technique      | ID    | Description                                    |
| -------------- | ----- | ---------------------------------------------- |
| Brute Force    | T1110 | Multiple login attempts via password guessing  |
| Valid Accounts | T1078 | Abuse of legitimate credentials to gain access |

---

## 🎉 Status: Resolved

Attack blocked. No successful access occurred.
✅ Devices scanned, isolated, and NSG hardened.
🛡️ Environment now has improved RDP access controls and detection thresholds.

---

