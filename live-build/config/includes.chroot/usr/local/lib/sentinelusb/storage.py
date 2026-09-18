#!/usr/bin/env python3
"""Writable report-storage helper.

SentinelUSB never repartitions a disk automatically. If a writable partition
with filesystem label SENTINELDATA exists, it may be mounted for reports.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

LABEL = "SENTINELDATA"
MOUNTPOINT = Path("/mnt/sentinel-data")
REPORTS = MOUNTPOINT / "Reports"


def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)


def data_device():
    link = Path("/dev/disk/by-label") / LABEL
    return link.resolve() if link.exists() else None


def is_mounted():
    result = run(["findmnt", "-rn", "-o", "SOURCE,TARGET", str(MOUNTPOINT)])
    return result.returncode == 0 and bool(result.stdout.strip())


def mount_data():
    device = data_device()
    if device is None:
        raise RuntimeError(
            "No writable SENTINELDATA partition found. Create a separate writable "
            "partition and give it the filesystem label SENTINELDATA."
        )
    MOUNTPOINT.mkdir(parents=True, exist_ok=True)
    if not is_mounted():
        result = run([
            "mount", "-o", "rw,nosuid,nodev,noexec",
            str(device), str(MOUNTPOINT)
        ])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Could not mount SENTINELDATA")
    REPORTS.mkdir(parents=True, exist_ok=True)
    return REPORTS


def report_root():
    try:
        return mount_data()
    except Exception:
        fallback = Path("/var/log/sentinelusb")
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def status():
    device = data_device()
    return {
        "label": LABEL,
        "device": str(device) if device else None,
        "mountpoint": str(MOUNTPOINT),
        "mounted": is_mounted(),
        "reports": str(REPORTS) if is_mounted() else None,
    }


if __name__ == "__main__":
    try:
        root = mount_data()
        print(f"SENTINELDATA mounted: {root}")
        print(f"Reports: {root / 'Reports'}")
    except Exception as exc:
        print(f"SENTINELDATA unavailable: {exc}")
        raise SystemExit(1)
