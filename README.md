# SentinelUSB

SentinelUSB is a small, bootable Linux security environment for inspecting Windows, Linux, and macOS systems for common malware and suspicious persistence.

## Design goals

- **Small USB footprint:** target a practical first ISO around 1–2 GB, with a stretch goal below 1 GB if the feature set permits.
- **Two operating modes:** a lightweight terminal mode for fast technical work and a simple graphical interface for guided scans.
- **Offline-first:** scanning should work without Internet access when current definitions/rules are already present.
- **Read-only by default:** target volumes are mounted read-only during analysis.
- **Established detection technology:** use ClamAV, YARA, hashes, and focused OS-specific persistence checks rather than inventing an antivirus engine.
- **Useful evidence:** produce HTML and JSON reports.

SentinelUSB is a defensive analysis and rescue tool. Only use it on systems you own or are authorized to inspect.

## Current status

The scanning engine supports OS-aware analysis profiles for Windows, Linux, and macOS. Common file scanning uses ClamAV and YARA; persistence analysis changes according to the detected operating system.

macOS support is intentionally best-effort at the filesystem layer: SentinelUSB can analyze a macOS volume when the Debian live environment can mount it read-only. APFS is handled with the userspace fsapfsmount utility; encrypted or inaccessible volumes are reported rather than force-mounted. Windows Registry startup and service artifacts are also checked when the relevant hives are readable.

## Planned workflow

1. Boot SentinelUSB from USB.
2. Detect storage devices and identify OS volumes.
3. Mount the target volume read-only.
4. Detect Windows, Linux, or macOS from filesystem markers.
5. Scan files with ClamAV and YARA.
6. Inspect OS-specific persistence locations.
7. Calculate hashes and collect findings.
8. Produce a portable HTML and JSON report.
9. Optionally quarantine selected files to writable external storage without automatically deleting evidence.

## Build

See [docs/BUILD.md](docs/BUILD.md).

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Scanning

See [docs/SCANNING.md](docs/SCANNING.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).\n\nFor persistent report storage, see [docs/STORAGE.md](docs/STORAGE.md).

## License

MIT.
