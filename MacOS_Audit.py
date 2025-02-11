import subprocess
import argparse
import os

def run_command(command, password=None):
    """Führt einen Shell-Befehl aus und gibt die Ausgabe zurück."""
    try:
        if password:
            command = f"echo {password} | sudo -S {command}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Fehler: {e}"

def check_setting(command, expected, description, password=None):
    """Führt den Befehl aus und prüft, ob die erwartete Ausgabe übereinstimmt."""
    output = run_command(command, password)
    if expected in output:
        print(f"[✔] {description}: AKTIVIERT")
    else:
        print(f"[✘] {description}: NICHT AKTIVIERT")

def check_admin_rights(password=None):
    """Prüft, ob der Benutzer Admin- oder Root-Rechte hat."""
    print("\n🔎 Überprüfung der Benutzerrechte...")

    admin_check = run_command("groups | grep -q admin && echo 'YES' || echo 'NO'")
    if admin_check == "YES":
        print("[⚠] Der aktuelle Benutzer ist ein Administrator!")
    else:
        print("[✔] Der aktuelle Benutzer ist KEIN Administrator.")

    sudo_check = run_command("sudo -l 2>/dev/null | grep '(ALL)'", password)
    if sudo_check:
        print("[⚠] Der Benutzer hat sudo-Rechte!")
    else:
        print("[✔] Der Benutzer hat KEINE sudo-Rechte.")

    root_check = run_command("dscl . -read /Users/root AuthenticationAuthority 2>/dev/null", password)
    if root_check:
        print("[⚠] Das Root-Konto ist AKTIVIERT!")
    else:
        print("[✔] Das Root-Konto ist deaktiviert.")

def check_suid_binaries(password=None):
    """Prüft auf gefährliche SUID-Binaries."""
    print("\n🔎 SUID-Binaries prüfen...")
    suid_binaries = run_command("find / -perm -4000 -type f 2>/dev/null", password)
    if suid_binaries:
        print("[⚠] Gefundene SUID-Binaries:")
        print(suid_binaries)
    else:
        print("[✔] Keine unsicheren SUID-Binaries gefunden.")

def check_weak_sudo_rules(password=None):
    """Prüft sudo-Regeln auf unsichere Einträge."""
    print("\n🔎 Schwache sudo-Regeln prüfen...")
    sudo_rules = run_command("sudo -l 2>/dev/null", password)
    if "NOPASSWD" in sudo_rules:
        print("[⚠] Es gibt sudo-Befehle ohne Passwort!")
        print(sudo_rules)
    else:
        print("[✔] Keine unsicheren sudo-Befehle gefunden.")

def check_cron_jobs(password=None):
    """Sucht nach Root-Cronjobs, die von normalen Usern bearbeitet werden können."""
    print("\n🔎 Cronjobs überprüfen...")
    cron_files = run_command("ls -l /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null", password)
    if cron_files:
        print("[⚠] Gefundene Cronjobs:")
        print(cron_files)
    else:
        print("[✔] Keine unsicheren Cronjobs gefunden.")

def check_writable_files(password=None):
    """Sucht nach sicherheitskritischen Dateien, die für alle beschreibbar sind."""
    print("\n🔎 Schreibbare sicherheitskritische Dateien suchen...")
    writable_files = run_command("find /etc/ -writable -type f 2>/dev/null", password)
    if writable_files:
        print("[⚠] Gefundene schreibbare Dateien:")
        print(writable_files)
    else:
        print("[✔] Keine unsicheren schreibbaren Dateien gefunden.")

def check_kernel_version():
    """Prüft die Kernel-Version für mögliche Exploits."""
    print("\n🔎 Kernel-Version überprüfen...")
    kernel_version = run_command("uname -a")
    print(f"🖥  Aktuelle Kernel-Version: {kernel_version}")
    print("👉 Falls veraltet, nach bekannten Exploits suchen!")

# Argumente verarbeiten
parser = argparse.ArgumentParser(description="macOS/Linux Security Audit")
parser.add_argument("-p", "--password", help="Sudo-Passwort für Befehle, die Admin-Rechte benötigen", type=str)
args = parser.parse_args()

password = args.password

# 🛡️ Sicherheitschecks starten
print("🔍 macOS/Linux Security Audit")

# Allgemeine Sicherheitsfunktionen
check_setting("defaults read /Library/Preferences/com.apple.alf globalstate", "1", "Firewall")
check_setting("defaults read /Library/Preferences/com.apple.alf stealthenabled", "1", "Stealth-Modus")
check_setting("spctl --status", "assessments enabled", "Gatekeeper")
check_setting("csrutil status", "enabled", "System Integrity Protection (SIP)")
check_setting("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled", "1", "Automatische Softwareupdates")

# Admin- & Root-Checks
check_admin_rights(password)

# Privilege Escalation Checks
check_suid_binaries(password)
check_weak_sudo_rules(password)
check_cron_jobs(password)
check_writable_files(password)
check_kernel_version()

print("\n✅ Überprüfung abgeschlossen!")
