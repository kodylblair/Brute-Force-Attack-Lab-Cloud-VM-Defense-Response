# 🔐 Brute Force Attack Lab: Cloud VM Defense Response

## 📅 Summary

Multiple virtual machines hosted in a cloud environment experienced brute force login attempts from public IP addresses. 

---

## 🔍 Analysis

### ⚡ Alert:

Seven different VMs showed signs of brute force login attempts from **eight unique public IPs**. The analysis focused on failed logins and potential compromises.

### 🧪 Brute Force Attempts:

| Virtual Machine                    | Attacker IP     | Logon Failures |
| ---------------------------------- | --------------- | -------------- |
| winwin10                           | 212.84.174.78   | 34             |
| jeff-lab-win-vm                    | 92.53.90.243    | 11             |
| jeff-lab-win-vm                    | 92.53.90.248    | 10             |
| jeff-lab-win-vm                    | 149.50.96.98    | 27             |
| saleh-mde-lab                      | 193.37.69.105   | 64             |
| linux-vmtest.internal.cloudapp.net | 103.215.221.225 | 13             |
| linux-vmtest.internal.cloudapp.net | 59.36.137.172   | 21             |

### 🕵️‍♂️ Logon Success Verification

Used the following Kusto query in Microsoft Defender for Endpoint to verify if any attacker IPs successfully authenticated:

```kusto
DeviceLogonEvents
| where RemoteIP in (
  "212.84.174.78", "92.53.90.243", "92.53.90.248",
  "149.50.96.98", "193.37.69.105", "103.215.221.225", "59.36.137.172"
)
| where ActionType == "LogonSuccess"
```

✅ **Result**: No successful logins were observed from any of the attacking IPs.

---

## ❌ Containment Actions

* Isolated all seven affected VMs using **Microsoft Defender for Endpoint (MDE)**.
* Ran **antimalware scans** across all impacted machines via MDE.
* Applied **NSG lockdown** to block RDP from public IPs, only allowing RDP from my personal home IP address.

---

## ⚖️ Policy Improvements

A new **corporate cloud security policy** was proposed:

* All VMs must restrict public RDP access by default.
* Only whitelisted, approved IPs (e.g., admin workstations or VPN) should be allowed.

---

## 💡 Key Takeaways

* Cloud-based VMs are high-value targets for brute force attacks.
* MDE's isolation and scanning capabilities make it effective for rapid containment.
* Network security groups (NSGs) are critical first-line defenses.
* Proactive policy changes are necessary to minimize future risk.

---

