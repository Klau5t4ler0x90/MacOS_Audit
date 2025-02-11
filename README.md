# 🔍 macOS/Linux Security Audit  

A lightweight and easy-to-use security audit tool for macOS and Linux. This script checks for common security vulnerabilities, misconfigurations, and privilege escalation risks on your system.  

## 🚀 Features  
- ✅ **Firewall & Security Checks**: Verifies if essential security features like Firewall, Gatekeeper, and SIP are enabled.  
- 🔎 **Admin & Root Access Verification**: Detects if the user has admin or sudo privileges.  
- 🛡 **Privilege Escalation Checks**: Scans for weak sudo rules, writable critical files, and SUID binaries.  
- 📋 **System Integrity & Kernel Check**: Ensures system integrity protection and checks the kernel version for possible exploits.  
- 🏗 **Automated Execution with Sudo Password Support**: Optionally pass the sudo password using `-p` or `--password` to avoid multiple prompts.  

## 📦 Installation & Usage  

Clone the repository:  
```bash
git clone https://github.com/yourusername/MacOS_Audit.git
cd MacOS_Audit
```

Run the script:

```bash
python3 MacOS_Audit.py
```

To provide the password upfront and avoid interruptions:

```bash
python3 MacOS_Audit.py -p yourpassword
```

⚠ Security Notice: Passing a password via the command line can be a security risk. Consider using a secure method to authenticate.


## 🤝 Contributing
Feel free to submit issues, fork the repository, and make pull requests! Any improvements or additional security checks are welcome.


## 📜 License
This project is licensed under the MIT License.


If you like my scripts:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/klau5t4ler0x90)
