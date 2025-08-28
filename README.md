# LAPS-UI (PowerShell/WPF) — Lightweight client to retrieve LAPS passwords

> **Why?**
> On **Windows 11**, the small graphical client "LAPS UI" is no longer officially available.
> This project offers a **lightweight, local and open-source alternative** to view **Windows LAPS** (new generation) and **Legacy LAPS** passwords directly from a workstation, **without the ActiveDirectory module**.

![Application preview](docs/screenshot.png)

---

## 📦 Provided

- **PowerShell script (.ps1)**: available **in the repository** (`LAPS-UI.ps1`).
- **Windows binary (.exe)**: available **in the _Releases_ tab** of this repository.

> ℹ️ The `.exe` binary provided in the releases **is not signed** (no code-signing).
> - Windows SmartScreen / some EDRs may display a warning or block execution.
> - Prefer the **.ps1** (signed by you) or sign the `.exe` before deploying in production.
> - Always verify the file's **SHA256 hash** (see below).

---

## ✨ Features

- 🔐 Read LAPS attributes in Active Directory via LDAP/LDAPS:
  - **Windows LAPS**: `msLAPS-Password` (+ expiration)
  - **Legacy LAPS**: `ms-Mcs-AdmPwd` (+ expiration)
- 🖥️ Modern **dark WPF UI** (Windows 10/11, DPI friendly).
- 🔎 Search by **computer name** (CN / sAMAccountName / dNSHostName).
- 🌐 **LDAP** by default or **LDAPS (TLS 636)** through a checkbox.
- 👁️ **Show/Hide** the password; **Copy** with **countdown** (20 s) and automatic clipboard purge.
- 🧠 **“Remember user”** option (stores *only* the user name in `%LOCALAPPDATA%\LAPS-UI\prefs.json`).
- ⚠️ **No password storage** on disk. No AD module required.

---

## ✅ Prerequisites

- **Windows 10/11**
- **Windows PowerShell 5.1**
- **.NET Framework 4.7+**
- Network access to a **domain controller** (LDAP 389 / LDAPS 636)
- **LAPS read rights** on the targeted **Computer** objects (ACL/GPO Microsoft LAPS)

---

## 🔧 Installation & Launch

### Option A — PowerShell script (recommended if SmartScreen/EDR is strict)
1. Get `LAPS-UI.ps1` from the repository.
2. (Optional) Unblock the file if needed:
   ```powershell
   Unblock-File .\LAPS-UI.ps1
   ```
3. Run in STA:
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -sta -File .\LAPS-UI.ps1
   ```

### Option B — Executable (.exe) from Releases
1. Download the desired version from the Releases tab.
2. Verify the SHA256 hash (example):
   ```powershell
   Get-FileHash .\LAPS-UI.exe -Algorithm SHA256 | Select-Object Hash
   ```
3. Run LAPS-UI.exe.
If SmartScreen/EDR blocks it: use the .ps1, sign the binary, or have it approved by your policies (AppLocker/WDAC/EDR).

---

## 🚀 Usage

1. User / Password: enter an account with LAPS read rights (or leave blank to try with your session credentials if your ACL allows it).
2. Controller/Domain: specify your DC/domain name.
3. LDAPS: check if your DC exposes 636/TLS with a valid certificate (recommended in production).
4. Computer name: enter the target PC (e.g. PC-IT-1234).
5. Click Retrieve → type of LAPS, expiration, and (if authorized) password appear.
6. Copy: the password is copied and a 20 s countdown automatically purges the clipboard.

---

## 🔒 Security

- No password is written to disk.
- The clipboard is purged after 20 s (if its content is still the copied password).
- Copy attempts to use the WinRT API (`IsAllowedInHistory=false`) to avoid the Win+V history.
- Depending on Windows/tenant settings, this exclusion may not be honored for non-packaged apps.  **100% effective solutions**: disable clipboard history via GPO, or package as a signed **MSIX**.
- The "Remember user" option only stores `UserName` and `RememberUser` in `%LOCALAPPDATA%\LAPS-UI\prefs.json`.

---

## 🧩 Troubleshooting (Quick FAQ)

### Not found / no LAPS attributes
- Check spelling, OU, and your LAPS read rights.
- Try **CN**, **sAMAccountName** (`...$`) or **dNSHostName**.

### LDAPS fails
- Valid server certificate? Port **636** open? **CN/SAN** of the cert = server name?
- Test first in **signed LDAP** (LDAPS box unchecked), then switch back to **LDAPS**.

### Password appears in Win+V
- Possible if Windows ignores `IsAllowedInHistory` outside **MSIX**.
  → Disable history via **GPO** or package as a signed **MSIX**.

### SmartScreen/EDR blocks the EXE
- Prefer the **PS1**, or **sign** the EXE and have it approved via **AppLocker/WDAC/EDR**.

---

## 🧪 Compatibility

- **Windows PowerShell 5.1**
- Not designed for **PowerShell 7** (WPF/WinRT differs)

