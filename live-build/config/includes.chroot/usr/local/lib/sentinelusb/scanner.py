#!/usr/bin/env python3
"""SentinelUSB scanning engine. Safe-by-default Windows volume scanning."""

from __future__ import annotations
import hashlib, html, json, os, shutil, subprocess, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True)

def list_block_devices():
    result = run(["lsblk","-J","-o","NAME,KNAME,PATH,TYPE,FSTYPE,LABEL,SIZE,RO,MOUNTPOINTS"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "lsblk failed")
    return json.loads(result.stdout).get("blockdevices", [])

def flatten_devices(nodes):
    out=[]
    for node in nodes:
        item=dict(node); children=item.pop("children",[])
        if item.get("type") in {"part","disk"}: out.append(item)
        out.extend(flatten_devices(children))
    return out

def find_windows_root(root):
    return sum((root/p).exists() for p in ["Windows","Users","Program Files"]) >= 2

def mount_read_only(device):
    mountpoint=Path(tempfile.mkdtemp(prefix="sentinelusb-"))
    result=run(["mount","-o","ro,nosuid,nodev,noexec",device,str(mountpoint)])
    if result.returncode != 0:
        shutil.rmtree(mountpoint,ignore_errors=True)
        raise RuntimeError(result.stderr.strip() or f"Could not mount {device} read-only")
    return mountpoint

def unmount(mountpoint):
    run(["umount",str(mountpoint)])

def sha256_file(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def persistence_checks(root):
    findings=[]
    paths=[root/"ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"]
    users=root/"Users"
    if users.is_dir():
        try:
            paths += [p/"AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
                      for p in users.iterdir() if p.is_dir() and p.name.lower() not in {"public","default","default user","all users"}]
        except PermissionError: pass
    for directory in paths:
        if directory.is_dir():
            try:
                for entry in directory.iterdir():
                    findings.append({"type":"startup_item","path":str(entry.relative_to(root)),
                                     "reason":"Item present in a Windows Startup folder"})
            except PermissionError: pass
    tasks=root/"Windows/System32/Tasks"
    if tasks.is_dir():
        try:
            for entry in tasks.rglob("*"):
                if entry.is_file():
                    findings.append({"type":"scheduled_task","path":str(entry.relative_to(root)),
                                     "reason":"Windows scheduled-task definition present"})
        except PermissionError: pass
    return findings

def run_clamav(root, report_dir):
    if shutil.which("clamscan") is None: return [{"engine":"clamav","error":"clamscan is not installed"}]
    log=report_dir/"clamav.log"
    result=subprocess.run(["clamscan","-r","--infected","--no-summary","--log",str(log),str(root)],
                          text=True,capture_output=True)
    detections=[]
    if log.exists():
        for line in log.read_text(errors="replace").splitlines():
            if ": " in line and line.rstrip().endswith(" FOUND"):
                path,label=line.rsplit(": ",1)
                detections.append({"engine":"clamav","path":path,"signature":label[:-6].strip()})
    if result.returncode not in (0,1):
        detections.append({"engine":"clamav","error":result.stderr.strip() or f"clamscan exited with {result.returncode}"})
    return detections

def run_yara(root,rules):
    if shutil.which("yara") is None: return [{"engine":"yara","error":"yara is not installed"}]
    result=run(["yara","-r",str(rules),str(root)])
    if result.returncode not in (0,1):
        return [{"engine":"yara","error":result.stderr.strip() or f"yara exited with {result.returncode}"}]
    return [{"engine":"yara","rule":p[0],"path":p[1]} for line in result.stdout.splitlines()
            if len(p:=line.split(maxsplit=1))==2]

def add_hashes(findings,root):
    for f in findings:
        raw=f.get("path")
        if not raw: continue
        path=Path(raw)
        if not path.is_absolute(): path=root/raw
        try:
            if path.is_file() and path.stat().st_size <= 256*1024*1024: f["sha256"]=sha256_file(path)
        except (OSError,PermissionError): pass

def write_html(report, path):
    rows=[]
    for finding in report.get('findings',[]):
        rows.append('<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>'.format(
            html.escape(str(finding.get('engine',finding.get('type','')))),
            html.escape(str(finding.get('rule',finding.get('signature',finding.get('reason',''))))),
            html.escape(str(finding.get('path',''))),
            html.escape(str(finding.get('sha256','')))))
    body=''.join(rows) or '<tr><td colspan="4">No findings reported.</td></tr>'
    page='''<!doctype html><html><head><meta charset="utf-8"><title>SentinelUSB Scan Report</title><style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ccc;padding:8px;text-align:left}code{word-break:break-all}</style></head><body><h1>SentinelUSB Scan Report</h1><p><b>Device:</b> {}</p><p><b>Mode:</b> READ-ONLY</p><p><b>Findings:</b> {}</p><table><tr><th>Engine</th><th>Detection</th><th>Path</th><th>SHA-256</th></tr>{}</table></body></html>'''.format(html.escape(report['device']),report['finding_count'],body)
    path.write_text(page)

def scan(device,rules,output_root):
    stamp=time.strftime('%Y-%m-%d_%H-%M-%S')
    output_dir=Path(output_root)/f'Scan_{stamp}'
    output_dir.mkdir(parents=True,exist_ok=True)
    mountpoint=mount_read_only(device)
    try:
        if not find_windows_root(mountpoint):
            raise RuntimeError("Mounted volume does not look like a Windows installation")
        persistence=persistence_checks(mountpoint)
        clam=run_clamav(mountpoint,output_dir)
        yara=run_yara(mountpoint,rules)
        findings=[x for x in clam+yara+persistence if "error" not in x]
        add_hashes(findings,mountpoint)
        report={"product":"SentinelUSB","version":"0.1.0",
                "started_at":datetime.now(timezone.utc).isoformat(),
                "completed_at":datetime.now(timezone.utc).isoformat(),
                "device":device,"mount_mode":"read-only","report_directory":str(output_dir),"finding_count":len(findings),
                "findings":findings,
                "engine_status":{"clamav":"ok" if not any(x.get("error") for x in clam) else "error",
                                 "yara":"ok" if not any(x.get("error") for x in yara) else "error"}}
        (output_dir/'report.json').write_text(json.dumps(report,indent=2))
        write_html(report, output_dir/'report.html')
        return report
    finally:
        try: unmount(mountpoint)
        finally: shutil.rmtree(mountpoint,ignore_errors=True)
