# Build Plan

## Base

SentinelUSB will use a minimal Debian live environment built with Debian live-build. We are not forking Tails.

A small desktop environment is optional. The base image should remain useful from a terminal so the graphical layer can be omitted or replaced without changing the scanner.

## Size strategy

The project will deliberately avoid bundling a large general-purpose desktop stack, office software, media tools, development environments, or multiple antivirus engines.

The first full-featured build should target roughly **1–2 GB compressed ISO size**, with optimization toward **sub-1 GB** where practical.

Size will be measured after every major dependency change.

## Core packages

The initial image is expected to include:

- Python 3
- ClamAV and its database tools
- YARA
- util-linux / lsblk
- udisks2
- NTFS support
- smartmontools
- jq
- basic filesystem and archive utilities

The GUI layer will use lightweight components and should not be required for scanning.

## Offline definitions

Virus definitions and YARA rules consume space. The build system should therefore support two modes:

- **Full image:** definitions included for offline scanning.
- **Slim image:** minimal scanner image with definitions updated before use.

The release documentation will clearly identify which mode an ISO provides.

## USB creation

Recommended process:

1. Download the ISO.
2. Verify its SHA-256 checksum.
3. Flash it to a USB drive with a tool such as balenaEtcher.
4. Boot the target machine from that USB.

Flashing an ISO normally erases the selected USB drive, so users must verify the destination before writing.

## Testing

Use the EICAR test file for safe antivirus detection testing. Do not use live malware samples in the repository or automated CI.
