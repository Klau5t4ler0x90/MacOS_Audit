import subprocess
import argparse
import re
import sys
import requests

def run_command(command, password=None):
    """Führt einen Shell-Befehl aus und gibt die Ausgabe und Returncode zurück."""
    try:
        if password and command.strip().startswith("sudo "):
            cmd = command.strip()[5:]
            command = f"echo {password} | sudo -S {cmd}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return f"Fehler: {e}", 1

def stream_linpeas():
    """Führt LinPEAS direkt aus und streamt die Ausgabe ins Terminal."""
    print("\n🌐 Starte LinPEAS (Benötigt Netzwerkverbindung)...")
    cmd = ["bash", "-c", "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        print(line, end='')
    proc.wait()
    if proc.returncode == 0:
        print("\n[✔] LinPEAS erfolgreich abgeschlossen.")
    else:
        print("\n[❌] LinPEAS fehlgeschlagen mit Code", proc.returncode)

def search_exploit_db(kernel_version):
    """Durchsucht Exploit-DB nach bekannten Kernel-Exploits."""
    print("\n🔎 Suche nach bekannten Kernel-Exploits in Exploit-DB...")
    try:
        url = f"https://www.exploit-db.com/search?q={kernel_version}"
        resp = requests.get(url)
        if resp.status_code == 200 and "No results found" not in resp.text:
            print(f"[⚠] Mögliche Exploits gefunden: {url}")
        else:
            print("[✔] Keine bekannten Exploits in der Exploit-DB gefunden.")
    except Exception as e:
        print(f"[❌] Fehler beim Abrufen der Exploit-DB: {e}")

def check_setting(command, expected, description, password=None):
    output, _ = run_command(command, password)
    print(f"[✔] {description}" if expected in output else f"[✘] {description}")

def check_admin_rights(password=None):
    print("\n🔎 Überprüfung der Benutzerrechte...")
    out, _ = run_command("groups | grep -q admin && echo YES || echo NO")
    print("[⚠] Admin-Benutzer" if out == "YES" else "[✔] Kein Administrator")
    out, _ = run_command("sudo -l 2>/dev/null | grep '(ALL)'", password)
    print("[⚠] sudo-Rechte vorhanden" if out else "[✔] Keine sudo-Rechte")
    out, _ = run_command("dscl . -read /Users/root AuthenticationAuthority 2>/dev/null", password)
    print("[⚠] Root-Konto aktiviert" if out else "[✔] Root-Konto deaktiviert")

def check_suid_binaries(password=None):
    print("\n🔎 SUID-Binaries prüfen...")
    out, _ = run_command("find / -perm -4000 -type f 2>/dev/null", password)
    print(out if out else "[✔] Keine unsicheren SUID-Binaries gefunden.")

def check_weak_sudo_rules(password=None):
    print("\n🔎 Schwache sudo-Regeln prüfen...")
    out, _ = run_command("sudo -l 2>/dev/null", password)
    print(out if "NOPASSWD" in out else "[✔] Keine unsicheren sudo-Befehle gefunden.")

def check_cron_jobs(password=None):
    print("\n🔎 Cronjobs überprüfen...")
    out, _ = run_command("ls -l /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null", password)
    print(out if out else "[✔] Keine unsicheren Cronjobs gefunden.")

def check_writable_files(password=None):
    print("\n🔎 Schreibbare sicherheitskritische Dateien suchen...")
    out, _ = run_command("find /etc/ -writable -type f 2>/dev/null", password)
    print(out if out else "[✔] Keine unsicheren schreibbaren Dateien gefunden.")

def check_kernel_version():
    print("\n🔎 Kernel-Version überprüfen...")
    out, _ = run_command("uname -r")
    print(f"🖥 Aktuelle Kernel-Version: {out}")
    return out

def get_output(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

def version_to_tuple(v):
    nums = re.findall(r'\d+', v)
    return tuple(int(x) for x in nums) if nums else ()

def check_version(current, minimum, description):
    curr, minv = version_to_tuple(current), version_to_tuple(minimum)
    status = "[✔]" if curr and curr >= minv else "[⚠]"
    comp = ">=" if status == "[✔]" else "<"
    print(f"{status} {description}: {current or 'unbekannt'} {comp} {minimum}")

# Argumente verarbeiten
parser = argparse.ArgumentParser(description="macOS/Linux Security Audit")
parser.add_argument("-p", "--password", type=str, help="Sudo-Passwort für Admin-Befehle")
parser.add_argument("-exploit", "--exploit", action="store_true",
                    help="Exploit-DB nach Kernel-Schwachstellen durchsuchen")
parser.add_argument("-linpeas", "--linpeas", action="store_true",
                    help="LinPEAS ausführen (streamt Ausgabe)")
args = parser.parse_args()
password = args.password
# LinPEAS optional
if args.linpeas:
    stream_linpeas()
print("\n🔍 macOS/Linux Security Audit")
# Checks
check_setting("defaults read /Library/Preferences/com.apple.alf globalstate", "1", "Firewall", password)
check_setting("defaults read /Library/Preferences/com.apple.alf stealthenabled", "1", "Stealth-Modus", password)
check_setting("spctl --status", "assessments enabled", "Gatekeeper", password)
check_setting("csrutil status", "enabled", "SIP", password)
check_setting("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled", "1", "Automatische Updates", password)
check_admin_rights(password)
check_suid_binaries(password)
check_weak_sudo_rules(password)
check_cron_jobs(password)
check_writable_files(password)
kernel_ver = check_kernel_version()
# CVE-Versionen prüfen
check_version(get_output("sudo --version | head -n1"), "1.9.17p1", "Sudo-Version (CVE-2025-32462/63)")
check_version(get_output("sw_vers -productVersion"), "15.5", "macOS Sequoia (CVE-2025-31259)")
check_version(get_output("sw_vers -productVersion"), "15.3", "macOS Sequoia (CVE-2025-24085)")
check_version(get_output("dpkg-query -W -f='${Version}' libblockdev 2>/dev/null || rpm -q --queryformat '%{VERSION}' libblockdev"), "2.28", "libblockdev (CVE-2025-6019)")
check_version(get_output("mdls -raw -name kMDItemVersion /Applications/Mozilla\\ VPN.app 2>/dev/null"), "2.28.0", "Mozilla VPN (CVE-2025-5687)")
# Exploit-DB optional
if args.exploit:
    search_exploit_db(kernel_ver)
print("\n✅ Überprüfung abgeschlossen!")
