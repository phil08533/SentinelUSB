# Threat Model

## Purpose

SentinelUSB is intended to inspect potentially compromised Windows computers from an independent boot environment.

## Threats addressed

- Common file-based malware
- Known malicious executables and scripts
- Suspicious startup artifacts
- Suspicious scheduled tasks and services
- Malware that prevents normal Windows security tools from operating
- Basic offline triage

## Threats not guaranteed to be addressed

- Firmware or UEFI compromise
- Hardware implants
- Every novel or fileless attack
- Malware hidden by sophisticated kernel-level rootkits
- Compromised firmware or storage controllers
- Encrypted evidence without available credentials

## Trust assumptions

The user controls the boot media and understands that a compromised target may contain misleading or hostile data.

SentinelUSB should minimize exposure to untrusted files by using read-only mounts and avoiding automatic execution of files from the target system.

## False positives

Findings are evidence for investigation, not automatic proof of compromise. Reports should preserve the detection source and reasoning.
