#!/usr/bin/env python3
"""SentinelUSB cross-platform scanning engine."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.4.0"


def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)


def list_block_devices():
    result = run(["lsblk", "-J", "-o", "NAME,KNAME,PATH,TYPE,FSTYPE,LABEL,SIZE,RO,MOUNTPOINTS"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "lsblk failed")
    return json.loads(result.stdout).get("blockdevices", [])


def flatten_devices(nodes):
    out = []
    for node in nodes:
        item = dict(node)
        children = item.pop("children", [])
        if item.get("type") in {"part", "disk"}:
            out.append(item)
        out.extend(flatten_devices(children))
    return out


def detect_os(root):
    windows = [root / "Windows", root / "Users", root / "Program Files"]
    linux = [root / "etc/os-release", root / "etc/systemd", root / "usr/bin", root / "var"]
    mac = [root / "System/Library", root / "Library", root / "Users", root / "Applications"]

    if sum(p.exists() for p in windows) >= 2:
        return "Windows"
    if sum(p.exists() for p in linux) >= 3:
        return "Linux"
    if sum(p.exists() for p in mac) >= 3 and (root / "System/Library").exists():
        return "macOS"
    return "Unknown"


def filesystem_type(device):
    result = run(["blkid", "-o", "value", "-s", "TYPE", device])
    return result.stdout.strip().lower() if result.returncode == 0 else ""


def _fuse_unmount(mountpoint):
    for command in (
        ["fusermount3", "-u", str(mountpoint)],
        ["fusermount", "-u", str(mountpoint)],
        ["umount", str(mountpoint)],
    ):
        if shutil.which(command[0]):
            result = run(command)
            if result.returncode == 0:
                return
    run(["umount", str(mountpoint)])


def mount_apfs_read_only(device):
    if shutil.which("fsapfsmount") is None:
        raise RuntimeError("APFS support is not installed (fsapfsmount missing)")

    errors = []
    for index in range(1, 17):
        mountpoint = Path(tempfile.mkdtemp(prefix=f"sentinelusb-apfs-{index}-"))
        result = run(["fsapfsmount", "-f", str(index), device, str(mountpoint)])
        if result.returncode != 0:
            errors.append(result.stderr.strip())
            shutil.rmtree(mountpoint, ignore_errors=True)
            continue
        if detect_os(mountpoint) == "macOS":
            return mountpoint
        _fuse_unmount(mountpoint)
        shutil.rmtree(mountpoint, ignore_errors=True)

    detail = next((e for e in errors if e), "no APFS volume matched macOS markers")
    raise RuntimeError(f"Could not access a macOS APFS system volume: {detail}")


def mount_read_only(device):
    fstype = filesystem_type(device)
    if fstype in {"apfs", "apfs_member"}:
        return mount_apfs_read_only(device)

    mountpoint = Path(tempfile.mkdtemp(prefix="sentinelusb-"))
    result = run(["mount", "-o", "ro,nosuid,nodev,noexec", device, str(mountpoint)])
    if result.returncode != 0:
        shutil.rmtree(mountpoint, ignore_errors=True)
        raise RuntimeError(result.stderr.strip() or f"Could not mount {device} read-only")
    return mountpoint


def unmount(mountpoint):
    _fuse_unmount(mountpoint)


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(directory, limit=5000):
    if not directory.is_dir():
        return
    count = 0
    try:
        for entry in directory.rglob("*"):
            if entry.is_file():
                yield entry
                count += 1
                if count >= limit:
                    break
    except (OSError, PermissionError):
        return


def windows_persistence_checks(root):
    findings = []
    paths = [root / "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"]
    users = root / "Users"
    if users.is_dir():
        try:
            paths += [
                p / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
                for p in users.iterdir()
                if p.is_dir() and p.name.lower() not in {"public", "default", "default user", "all users"}
            ]
        except PermissionError:
            pass

    for directory in paths:
        for entry in _iter_files(directory, 1000) or []:
            findings.append({
                "type": "startup_item",
                "path": str(entry.relative_to(root)),
                "reason": "Item present in a Windows Startup folder",
                "severity": "medium",
            })

    tasks = root / "Windows/System32/Tasks"
    for entry in _iter_files(tasks, 5000) or []:
        findings.append({
            "type": "scheduled_task",
            "path": str(entry.relative_to(root)),
            "reason": "Windows scheduled-task definition present",
            "severity": "low",
        })

    findings.extend(windows_registry_checks(root))
    return findings


def _registry_values(hive, key):
    if shutil.which("hivexget") is None:
        return []
    result = run(["hivexget", str(hive), key])
    if result.returncode != 0:
        return []
    values = []
    for line in result.stdout.splitlines():
        match = re.match(r'^"([^"]+)"=', line.strip())
        if match:
            values.append((match.group(1), line.strip()))
    return values


def _registry_string_value(hive, key, name):
    if shutil.which("hivexget") is None:
        return ""
    result = run(["hivexget", str(hive), key, name])
    return result.stdout.strip() if result.returncode == 0 else ""


def _registry_findings(hive, key, reason, severity="medium"):
    findings = []
    for name, raw in _registry_values(hive, key):
        findings.append({
            "type": "registry_persistence",
            "path": f"{hive.name}:{key}:{name}",
            "reason": reason,
            "value": raw[:1000],
            "severity": severity,
        })
    return findings


def _current_control_set(system_hive):
    value = _registry_string_value(system_hive, r"\Select", "Current")
    try:
        number = int(value)
        return f"ControlSet{number:03d}"
    except ValueError:
        return "ControlSet001"


def _service_registry_findings(system_hive):
    if shutil.which("hivexregedit") is None:
        return []
    control = _current_control_set(system_hive)
    result = run([
        "hivexregedit", "--export", "--max-depth", "2",
        str(system_hive), rf"\{control}\Services"
    ])
    if result.returncode != 0:
        return []

    findings = []
    current_service = None
    for line in result.stdout.splitlines():
        section = re.match(r"^\[(.+)\]$", line.strip())
        if section:
            current_service = section.group(1)
            continue
        if current_service and re.search(r'"(ImagePath|ServiceDll)"=', line, re.I):
            findings.append({
                "type": "service_registry",
                "path": f"{system_hive.name}:{current_service}",
                "reason": "Windows service registry entry contains an executable or service DLL path",
                "value": line.strip()[:1000],
                "severity": "medium",
            })
    return findings[:2000]


def windows_registry_checks(root):
    findings = []
    software = root / "Windows/System32/config/SOFTWARE"
    system = root / "Windows/System32/config/SYSTEM"

    if software.is_file():
        for key in (
            r"\Microsoft\Windows\CurrentVersion\Run",
            r"\Microsoft\Windows\CurrentVersion\RunOnce",
            r"\Microsoft\Windows\CurrentVersion\RunOnceEx",
            r"\Microsoft\Windows NT\CurrentVersion\Winlogon",
        ):
            reason = "Windows Registry startup or logon value present"
            findings.extend(_registry_findings(software, key, reason))

    if system.is_file():
        findings.extend(_service_registry_findings(system))

    if users.is_dir():
        try:
            user_dirs = [p for p in users.iterdir() if p.is_dir()]
        except PermissionError:
            user_dirs = []
        for user in user_dirs[:100]:
            hive = user / "NTUSER.DAT"
            if not hive.is_file():
                continue
            for key in (
                r"\Software\Microsoft\Windows\CurrentVersion\Run",
                r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
            ):
                findings.extend(_registry_findings(
                    hive, key, "User Registry startup value present"
                ))
    return findings


def linux_persistence_checks(root):
    findings = []
    directories = [
        (root / "etc/systemd/system", "systemd service"),
        (root / "etc/systemd/user", "systemd user service"),
        (root / "etc/cron.d", "cron definition"),
        (root / "etc/cron.daily", "daily cron job"),
        (root / "etc/cron.hourly", "hourly cron job"),
        (root / "etc/cron.weekly", "weekly cron job"),
        (root / "etc/cron.monthly", "monthly cron job"),
        (root / "etc/init.d", "SysV init script"),
    ]
    for directory, kind in directories:
        for entry in _iter_files(directory, 2000) or []:
            findings.append({
                "type": "persistence",
                "path": str(entry.relative_to(root)),
                "reason": f"Linux {kind} found",
                "severity": "low",
            })

    users = root / "home"
    if users.is_dir():
        try:
            user_dirs = list(users.iterdir())
        except PermissionError:
            user_dirs = []
        for user in user_dirs[:100]:
            if not user.is_dir():
                continue
            for rel in [".config/autostart", ".bashrc", ".bash_profile", ".profile", ".zshrc"]:
                target = user / rel
                if target.is_file():
                    findings.append({
                        "type": "user_startup",
                        "path": str(target.relative_to(root)),
                        "reason": "Linux user startup configuration found",
                        "severity": "low",
                    })
                elif target.is_dir():
                    for entry in _iter_files(target, 1000) or []:
                        findings.append({
                            "type": "user_startup",
                            "path": str(entry.relative_to(root)),
                            "reason": "Linux user autostart entry found",
                            "severity": "low",
                        })
            for entry in _iter_files(user / ".ssh", 100) or []:
                if entry.name in {"authorized_keys", "authorized_keys2"}:
                    findings.append({
                        "type": "ssh_persistence",
                        "path": str(entry.relative_to(root)),
                        "reason": "SSH authorized_keys file can provide persistent remote access",
                        "severity": "medium",
                    })
    return findings


def macos_persistence_checks(root):
    findings = []
    locations = [
        (root / "Library/LaunchAgents", "macOS LaunchAgent"),
        (root / "Library/LaunchDaemons", "macOS LaunchDaemon"),
        (root / "System/Library/LaunchAgents", "macOS system LaunchAgent"),
        (root / "System/Library/LaunchDaemons", "macOS system LaunchDaemon"),
    ]
    users = root / "Users"
    if users.is_dir():
        try:
            for user in users.iterdir():
                if user.is_dir() and user.name not in {"Shared", ".localized"}:
                    locations.append((user / "Library/LaunchAgents", "macOS user LaunchAgent"))
        except PermissionError:
            pass

    for directory, kind in locations:
        for entry in _iter_files(directory, 2000) or []:
            findings.append({
                "type": "persistence",
                "path": str(entry.relative_to(root)),
                "reason": f"{kind} found",
                "severity": "medium",
            })

    profiles = root / "Library/Profiles"
    for entry in _iter_files(profiles, 1000) or []:
        findings.append({
            "type": "configuration_profile",
            "path": str(entry.relative_to(root)),
            "reason": "macOS configuration profile found",
            "severity": "medium",
        })
    return findings


def persistence_checks(root, os_name):
    if os_name == "Windows":
        return windows_persistence_checks(root)
    if os_name == "Linux":
        return linux_persistence_checks(root)
    if os_name == "macOS":
        return macos_persistence_checks(root)
    return []


def run_clamav(root, report_dir):
    if shutil.which("clamscan") is None:
        return [{"engine": "clamav", "error": "clamscan is not installed"}]
    log = report_dir / "clamav.log"
    result = subprocess.run(
        ["clamscan", "-r", "--infected", "--no-summary", "--log", str(log), str(root)],
        text=True,
        capture_output=True,
    )
    detections = []
    if log.exists():
        for line in log.read_text(errors="replace").splitlines():
            if ": " in line and line.rstrip().endswith(" FOUND"):
                path, label = line.rsplit(": ", 1)
                detections.append({
                    "engine": "clamav",
                    "path": path,
                    "signature": label[:-6].strip(),
                    "severity": "high",
                })
    if result.returncode not in (0, 1):
        detections.append({
            "engine": "clamav",
            "error": result.stderr.strip() or f"clamscan exited with {result.returncode}",
        })
    return detections


def run_yara(root, rules):
    if shutil.which("yara") is None:
        return [{"engine": "yara", "error": "yara is not installed"}]
    result = run(["yara", "-r", str(rules), str(root)])
    if result.returncode not in (0, 1):
        return [{
            "engine": "yara",
            "error": result.stderr.strip() or f"yara exited with {result.returncode}",
        }]
    findings = []
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            findings.append({
                "engine": "yara",
                "rule": parts[0],
                "path": parts[1],
                "severity": "medium",
            })
    return findings


def add_hashes(findings, root):
    for finding in findings:
        raw = finding.get("path")
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute():
            path = root / raw
        try:
            if path.is_file() and path.stat().st_size <= 256 * 1024 * 1024:
                finding["sha256"] = sha256_file(path)
        except (OSError, PermissionError):
            pass


def write_html(report, path):
    rows = []
    for finding in report.get("findings", []):
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(
                html.escape(str(finding.get("engine", finding.get("type", "")))),
                html.escape(str(finding.get("severity", ""))),
                html.escape(str(finding.get("rule", finding.get("signature", finding.get("reason", ""))))),
                html.escape(str(finding.get("path", ""))),
                html.escape(str(finding.get("sha256", ""))),
            )
        )
    body = "".join(rows) or '<tr><td colspan="5">No findings reported.</td></tr>'
    page = """<!doctype html><html><head><meta charset="utf-8">
<title>SentinelUSB Scan Report</title>
<style>body{font:15px system-ui,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px}
table{width:100%;border-collapse:collapse}th,td{border:1px solid #ccc;padding:8px;text-align:left}
code{word-break:break-all}.meta{line-height:1.7}</style></head><body>
<h1>SentinelUSB Scan Report</h1>
<div class="meta"><p><b>Device:</b> {}</p><p><b>Detected OS:</b> {}</p>
<p><b>Mode:</b> READ-ONLY</p><p><b>Findings:</b> {}</p>
<p><b>Started:</b> {}</p><p><b>Completed:</b> {}</p></div>
<table><tr><th>Engine</th><th>Severity</th><th>Detection</th><th>Path</th><th>SHA-256</th></tr>{}</table>
</body></html>""".format(
        html.escape(report["device"]),
        html.escape(report["os"]),
        report["finding_count"],
        html.escape(report["started_at"]),
        html.escape(report["completed_at"]),
        body,
    )
    path.write_text(page, encoding="utf-8")


def scan(device, rules, output_root, progress=None):
    def say(message):
        if progress:
            progress(message)

    started = datetime.now(timezone.utc).isoformat()
    say("Mounting target read-only...")
    mountpoint = mount_read_only(device)
    output_dir = None
    try:
        os_name = detect_os(mountpoint)
        say(f"Detected operating system: {os_name}")
        if os_name == "Unknown":
            raise RuntimeError(
                "Mounted volume could not be identified as Windows, Linux, or macOS. "
                "The filesystem may be unsupported, encrypted, or not an OS volume."
            )

        stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        output_dir = Path(output_root) / f"Scan_{stamp}"
        output_dir.mkdir(parents=True, exist_ok=True)

        say("Checking persistence locations...")
        persistence = persistence_checks(mountpoint, os_name)

        say("Running ClamAV...")
        clam = run_clamav(mountpoint, output_dir)

        say("Running YARA...")
        yara = run_yara(mountpoint, rules)

        findings = [x for x in clam + yara + persistence if "error" not in x]
        add_hashes(findings, mountpoint)

        completed = datetime.now(timezone.utc).isoformat()
        report = {
            "product": "SentinelUSB",
            "version": VERSION,
            "started_at": started,
            "completed_at": completed,
            "device": device,
            "os": os_name,
            "mount_mode": "read-only",
            "report_directory": str(output_dir),
            "finding_count": len(findings),
            "findings": findings,
            "engine_status": {
                "clamav": "ok" if not any(x.get("error") for x in clam) else "error",
                "yara": "ok" if not any(x.get("error") for x in yara) else "error",
                "registry": "available" if shutil.which("hivexget") else "unavailable",
                "service_registry": "available" if shutil.which("hivexregedit") else "unavailable",
                "apfs": "available" if shutil.which("fsapfsmount") else "unavailable",
            },
        }
        (output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        write_html(report, output_dir / "report.html")
        say("Report written.")
        return report
    finally:
        try:
            unmount(mountpoint)
        finally:
            shutil.rmtree(mountpoint, ignore_errors=True)
