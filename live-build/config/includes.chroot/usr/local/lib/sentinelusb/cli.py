#!/usr/bin/env python3
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from scanner import VERSION, flatten_devices, list_block_devices, scan
from storage import report_root, status as storage_status

BANNER = r'''
              /\\
             /  \\
            / /\\ \\
           / /  \\ \\
          / /====\\ \\
         /_/      \\_\\
             ||||
             ||||
             ||||
            /||||\\
           /_||||_\\
          /  ||||  \
         /___||||___\\
             /\
            /  \
        SENTINELUSB
'''

RULES = Path("/usr/local/share/sentinelusb/rules/sentinel.yar")


def help_text():
    print("""
Commands:
  help                 Show this help
  version              Show SentinelUSB version
  drives               List disks and partitions
  storage              Show persistent report-storage status
  scan <device>        Scan a Windows, Linux, or macOS volume read-only
  update               Update ClamAV definitions when online
  gui                  Launch the graphical scanner
  exit                 Leave SentinelUSB

Example:
  drives
  storage
  scan /dev/nvme0n1p3
""")


def show_drives():
    devices = flatten_devices(list_block_devices())
    print("\nDetected storage:")
    for d in devices:
        print(
            f"  {d.get('path','?'):<22} "
            f"{d.get('type','?'):<6} "
            f"{d.get('fstype') or '-':<10} "
            f"{d.get('size') or '-':<10} "
            f"{d.get('label') or '-'}"
        )
    print()


def show_storage():
    s = storage_status()
    print("\nPersistent report storage:")
    print(f"  Label:       {s['label']}")
    print(f"  Device:      {s['device'] or 'not found'}")
    print(f"  Mountpoint:  {s['mountpoint']}")
    print(f"  Mounted:     {'yes' if s['mounted'] else 'no'}")
    print(f"  Reports:     {s['reports'] or 'fallback until mounted'}")
    print()


def do_scan(device):
    if os.geteuid() != 0:
        print("Scan requires root privileges. Start the SentinelUSB shell as root.")
        return
    if not Path(device).exists():
        print(f"Device not found: {device}")
        return

    reports = report_root()
    print(f"\n[+] Scanning {device}")
    print("[+] Target will be mounted read-only.")
    print(f"[+] Reports: {reports}")
    print("[+] ClamAV + YARA + OS-specific persistence checks are running.")

    try:
        report = scan(
            device,
            RULES,
            reports,
            lambda message: print(f"[+] {message}")
        )
    except Exception as exc:
        print(f"[!] Scan failed: {exc}")
        return

    print(f"\n[+] Scan complete: {report['finding_count']} finding(s)")
    print(f"[+] Detected OS: {report['os']}")
    print("[+] Report directory:", report["report_directory"])
    print("[+] HTML report:", Path(report["report_directory"]) / "report.html")
    print("[+] JSON report:", Path(report["report_directory"]) / "report.json")
    print("[+] ClamAV log:", Path(report["report_directory"]) / "clamav.log")



def update_clamav():
    if os.geteuid() != 0:
        print("ClamAV update requires root privileges.")
        return
    if not shutil.which("freshclam"):
        print("[!] freshclam is not installed.")
        return
    print("[+] Updating ClamAV definitions...")
    result = subprocess.run(["freshclam"], text=True)
    if result.returncode == 0:
        print("[+] ClamAV definitions updated.")
    else:
        print(f"[!] freshclam exited with {result.returncode}. The machine may be offline or the update server may be unavailable.")

def launch_gui():
    if os.geteuid() != 0:
        print("GUI requires root privileges.")
        return
    subprocess.run(["/usr/local/bin/sentinelusb-gui"])


def dispatch(parts):
    if not parts:
        return True

    cmd = parts[0].lower()
    if cmd in {"exit", "quit"}:
        return False
    if cmd == "help":
        help_text()
    elif cmd == "version":
        print(f"SentinelUSB {VERSION}")
    elif cmd == "drives":
        try:
            show_drives()
        except Exception as exc:
            print(f"[!] Could not enumerate drives: {exc}")
    elif cmd == "storage":
        try:
            show_storage()
        except Exception as exc:
            print(f"[!] Storage status failed: {exc}")
    elif cmd == "scan" and len(parts) == 2:
        do_scan(parts[1])
    elif cmd == "update" and len(parts) == 1:
        update_clamav()
    elif cmd == "gui" and len(parts) == 1:
        launch_gui()
    else:
        print("Unknown command. Type 'help'.")
    return True


def main():
    print(BANNER)
    print("  SENTINELUSB SECURITY RESCUE ENVIRONMENT")
    print("  ========================================")
    print(f"  Version {VERSION}")
    print("  Type 'help' for available commands.")

    if len(sys.argv) > 1:
        dispatch(sys.argv[1:])
        return

    while True:
        try:
            parts = shlex.split(input("\nsentinel> "))
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not dispatch(parts):
            break


if __name__ == "__main__":
    main()
