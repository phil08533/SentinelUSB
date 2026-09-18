#!/usr/bin/env python3
import os, sys
from pathlib import Path
from scanner import flatten_devices, list_block_devices, scan

BANNER = r'''
______________$$$$$$$$$$____________________
_____________$$__$_____$$$$$________________
_____________$$_$$__$$____$$$$$$$$__________
____________$$_$$__$$$$$________$$$_________
___________$$_$$__$$__$$_$$$__$$__$$________
___________$$_$$__$__$$__$$$$$$$$__$$_______
____________$$$$$_$$_$$$_$$$$$$$$_$$$_______
_____________$$$$$$$$$$$$$_$$___$_$$$$______
________________$$_$$$______$$$$$_$$$$______
_________________$$$$_______$$$$$___$$$$____
___________________________$$_$$____$$$$____
___________________________$$_$$____$$$$$___
__________________________$$$$$_____$$$$$$__
_________________________$__$$_______$$$$$__
________________________$$$_$$________$$$$$_
________________________$$$___________$$$$$_
_________________$$$$___$$____________$$$$$$
__$$$$$$$$____$$$$$$$$$$_$____________$$$_$$
_$$$$$$$$$$$$$$$______$$$$$$$___$$____$$_$$$
$$________$$$$__________$_$$$___$$$_____$$$$
$$______$$$_____________$$$$$$$$$$$$$$$$$_$$
$$______$$_______________$$_$$$$$$$$$$$$$$$_
$$_____$_$$$$$__________$$$_$$$$$$$$$$$$$$$_
$$___$$$__$$$$$$$$$$$$$$$$$__$$$$$$$$$$$$$__
$$_$$$$_____$$$$$$$$$$$$________$$$$$$__$___
$$$$$$$$$$$$$$_________$$$$$______$$$$$$$___
$$$$_$$$$$______________$$$$$$$$$$$$$$$$____
$$__$$$$_____$$___________$$$$$$$$$$$$$_____
$$_$$$$$$$$$$$$____________$$$$$$$$$$_______
$$_$$$$$$$hg$$$____$$$$$$$$__$$$____________
$$$$__$$$$$$$$$$$$$$$$$$$$$$$$______________
$$_________$$$$$$$$$$$$$$$__________________
'''

RULES=Path("/usr/local/share/sentinelusb/rules/sentinel.yar")
REPORTS=Path("/run/live/medium/Reports")
# The live ISO itself is read-only; use a writable Reports directory on the boot medium when available.\nif not os.access(REPORTS.parent, os.W_OK):\n    REPORTS=Path("/var/log/sentinelusb")

def help_text():
    print("""
Commands:
  help              Show this help
  version           Show SentinelUSB version
  drives            List disks and partitions
  scan <device>     Scan a Windows volume read-only
  exit              Leave SentinelUSB

Example:
  drives
  scan /dev/nvme0n1p3
""")

def show_drives():
    devices=flatten_devices(list_block_devices())
    print("\nDetected storage:")
    for d in devices:
        print(f"  {d.get('path','?'):<18} {d.get('type','?'):<6} {d.get('fstype') or '-':<10} {d.get('size') or '-':<10} {d.get('label') or '-'}")
    print()

def do_scan(device):
    if os.geteuid()!=0:
        print("Scan requires root privileges. Start the SentinelUSB shell as root.")
        return
    if not Path(device).exists():
        print(f"Device not found: {device}")
        return
    print(f"\n[+] Scanning {device}")
    print("[+] Target will be mounted read-only.")
    print("[+] ClamAV + YARA + persistence checks are running.")
    try:
        report=scan(device,RULES,REPORTS)
    except Exception as exc:
        print(f"[!] Scan failed: {exc}")
        return
    print(f"\n[+] Scan complete: {report['finding_count']} finding(s)")
    print("[+] Report directory:", report["report_directory"])
    print("[+] HTML report:", Path(report["report_directory"]) / "report.html")
    print(f"[+] ClamAV log:  {REPORTS/'clamav.log'}")

def dispatch(parts):
    if not parts: return True
    cmd=parts[0].lower()
    if cmd in {"exit","quit"}: return False
    if cmd=="help": help_text()
    elif cmd=="version": print("SentinelUSB 0.1.0")
    elif cmd=="drives":
        try: show_drives()
        except Exception as exc: print(f"[!] Could not enumerate drives: {exc}")
    elif cmd=="scan" and len(parts)==2: do_scan(parts[1])
    else: print("Unknown command. Type 'help'.")
    return True

def main():
    print(BANNER)
    print("  SENTINELUSB SECURITY RESCUE ENVIRONMENT")
    print("  ========================================")
    print("  Type 'help' for available commands.")
    if len(sys.argv)>1:
        dispatch(sys.argv[1:])
        return
    while True:
        try: parts=input("\nsentinel> ").strip().split()
        except (EOFError,KeyboardInterrupt): print(); break
        if not dispatch(parts): break

if __name__=="__main__": main()
