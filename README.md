# 🔍 macOS/Linux Security Audit

A lightweight, script-based security audit tool for macOS and Linux. In seconds, it checks common hardening measures, privilege escalation risks, and known vulnerabilities.

## 🚀 Features

- **🛡 Core Hardening Checks**  
  Verifies firewall, stealth mode, Gatekeeper, SIP, and automatic updates—no admin prompt required.

- **🔑 Admin & Root Privilege Verification**  
  Detects if the current user has admin or sudo privileges and if the root account is enabled.

- **⚡ Privilege Escalation Checks**  
  Scans for:  
  - Unsafe SUID binaries  
  - Weak `sudo` rules (`NOPASSWD`)  
  - Editable Cronjobs  
  - World-writable system files

- **🔍 CVE Version Scans**  
  Compares installed versions of Sudo, macOS, libblockdev, and Mozilla VPN against minimal patched releases for 2025 CVEs to identify missing updates.

- **🌐 Optional Exploit-DB Lookup**  
  With `--exploit`, looks up the installed kernel version in the Exploit-DB and displays direct links for any matches.

- **🧰 LinPEAS Integration**  
  `--linpeas` streams LinPEAS live in the terminal for deeper system scanning.

- **🔒 Sudo Password Support**  
  Use `-p | --password` to pass the sudo password up front and avoid multiple prompts.

## 📦 Installation

```bash
git clone https://github.com/yourusername/MacOS_Audit.git
cd MacOS_Audit
chmod +x MacOS_Audit.py
```

## ⚙️ Usage

```bash
# Basic scan (no password prompt)
python3 MacOS_Audit.py

# Pass sudo password up front
python3 MacOS_Audit.py -p YourSudoPassword

# Enable Exploit-DB lookup
python3 MacOS_Audit.py --exploit

# Stream LinPEAS live
python3 MacOS_Audit.py --linpeas

# Combine all options
python3 MacOS_Audit.py -p YourPassword --exploit --linpeas
```

> **⚠ Warning:** Passing passwords via CLI can be stored in shell history. For high security, use temporary sessions or a secure credential manager.

## 🤝 Contributing

Contributions, ideas, and additional checks are welcome! Create an issue or submit a pull request.

## 📜 License

MIT License © Your Name

---

If you find this tool helpful, consider buying me a coffee:  
[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/klau5t4ler0x90)
