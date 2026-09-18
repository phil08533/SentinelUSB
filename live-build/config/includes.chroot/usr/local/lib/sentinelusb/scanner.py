#!/usr/bin/env python3
"""SentinelUSB cross-platform scanning engine.

Targets Windows, Linux, and macOS volumes when the live environment can
mount/read the filesystem. Scanning is read-only and uses common engines
plus OS-specific persistence checks.
"""

from __future__ import annotations
import hashlib, html, json, os, shutil, subprocess, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.2.0"


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
    """Return a best-effort OS profile based on filesystem markers."""
    windows_markers = [
        root / "Windows",
        root / "Users",
        root / "Program Files",
    ]
    linux_markers = [
        root / "etc/os-release",
        root / "etc/systemd",
        root / "usr/bin",
        root / "var",
    ]
    mac_markers = [
        root / "System/Library",
        root / "Library",
        root / "Users",
        root / "Applications",
    ]

    if sum(p.exists() for p in windows_markers) >= 2:
        return "Windows"
    if sum(p.exists() for p in linux_markers) >= 3:
        return "Linux"
    if sum(p.exists() for p in mac_markers) >= 3 and (root / "System/Library").exists():
        return "macOS"
    return "Unknown"


def mount_read_only(device):
    mountpoint = Path(tempfile.mkdtemp(prefix="sentinelusb-"))
    result = run(["mount", "-o", "ro,nosuid,nodev,noexec", device, str(mountpoint)])
    if result.returncode != 0:
        shutil.rmtree(mountpoint, ignore_errors=True)
        raise RuntimeError(result.stderr.strip() or f"Could not mount {device} read-only")
    return mountpoint


def unmount(mountpoint):
    run(["umount", str(mountpoint)])


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(directory, limit=5000):
    """Yield a bounded set of files so persistence checks cannot explode."""
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
        for entry in _iter_files(directory, limit=1000) or []:
            findings.append({
                "type": "startup_item",
                "path": str(entry.relative_to(root)),
                "reason": "Item present in a Windows Startup folder",
                "severity": "medium",
            })

    tasks = root / "Windows/System32/Tasks"
    for entry in _iter_files(tasks, limit=5000) or []:
        findings.append({
            "type": "scheduled_task",
            "path": str(entry.relative_to(root)),
            "reason": "Windows scheduled-task definition present",
            "severity": "low",
        })
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
        for entry in _iter_files(directory, limit=2000) or []:
            findings.append({
                "type": "persistence",
                "path": str(entry.relative_to(root)),
                "reason": f"Linux {kind} found",
                "severity": "low",
            })

    users = root / "home"
    for user in users.iterdir() if users.is_dir() else []:
        if not user.is_dir():
            continue
        for rel in [
            ".config/autostart",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
        ]:
            target = user / rel
            if target.is_file():
                findings.append({
                    "type": "user_startup",
                    "path": str(target.relative_to(root)),
                    "reason": "Linux user startup configuration found",
                    "severity": "low",
                })
            elif target.is_dir():
                for entry in _iter_files(target, limit=1000) or []:
                    findings.append({
                        "type": "user_startup",
                        "path": str(entry.relative_to(root)),
                        "reason": "Linux user autostart entry found",
                        "severity": "low",
                    })

    ssh = users
    for entry in _iter_files(ssh, limit=5000) or []:
        if entry.name == "authorized_keys" or entry.name == "authorized_keys2":
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
        for entry in _iter_files(directory, limit=2000) or []:
            findings.append({
                "type": "persistence",
                "path": str(entry.relative_to(root)),
                "reason": f"{kind} found",
                "severity": "medium",
            })

    profiles = root / "Library/Profiles"
    for entry in _iter_files(profiles, limit=1000) or []:
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
code{word-break:break-all} .meta{line-height:1.7}</style></head><body>
<h1>SentinelUSB Scan Report</h1>
<div class="meta"><p><b>Device:</b> {}</p><p><b>Detected OS:</b> {}</p>
<p><b>Mode:</b> READ-ONLY</p><p><b>Findings:</b> {}</p></div>
<table><tr><th>Engine</th><th>Severity</th><th>Detection</th><th>Path</th><th>SHA-256</th></tr>{}</table>
</body></html>""".format(
        html.escape(report["device"]),
        html.escape(report["os"]),
        report["finding_count"],
        body,
    )
    path.write_text(page)


def scan(device, rules, output_root):
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = Path(output_root) / f"Scan_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    mountpoint = mount_read_only(device)
    try:
        os_name = detect_os(mountpoint)
        if os_name == "Unknown":
            raise RuntimeError(
                "Mounted volume could not be identified as Windows, Linux, or macOS. "
                "The filesystem may be unsupported, encrypted, or not an OS volume."
            )
        persistence = persistence_checks(mountpoint, os_name)
        clam = run_clamav(mountpoint, output_dir)
        yara = run_yara(mountpoint, rules)
        findings = [x for x in clam + yara + persistence if "error" not in x]
        add_hashes(findings, mountpoint)
        report = {
            "product": "SentinelUSB",
            "version": VERSION,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "device": device,
            "os": os_name,
            "mount_mode": "read-only",
            "report_directory": str(output_dir),
            "finding_count": len(findings),
            "findings": findings,
            "engine_status": {
                "clamav": "ok" if not any(x.get("error") for x in clam) else "error",
                "yara": "ok" if not any(x.get("error") for x in yara) else "error",
            },
        }
        (output_dir / "report.json").write_text(json.dumps(report, indent=2))
        write_html(report, output_dir / "report.html")
        return report
    finally:
        try:
            unmount(mountpoint)
        finally:
            shutil.rmtree(mountpoint, ignore_errors=True)
