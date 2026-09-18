# SentinelUSB

SentinelUSB is a small, bootable Linux security environment for inspecting Windows systems for common malware and suspicious persistence.

## Design goals

- **Small USB footprint:** target a practical first ISO around 1–2 GB, with a stretch goal below 1 GB if the feature set permits.
- **Two operating modes:** a lightweight terminal mode for fast technical work and a simple graphical interface for guided scans.
- **Offline-first:** scanning should work without Internet access when current definitions/rules are already present.
- **Read-only by default:** the target Windows volume should be mounted read-only during analysis.
- **Established detection technology:** use ClamAV, YARA, hashes, and focused Windows persistence checks rather than inventing an antivirus engine.
- **Useful evidence:** produce HTML and JSON reports.

SentinelUSB is a defensive analysis and rescue tool. Only use it on systems you own or are authorized to inspect.

## Current status

Early project setup. The architecture and build plan are being established before the scanning engine is implemented.

## Planned workflow

1. Boot SentinelUSB from USB.
2. Detect internal storage and Windows installations.
3. Mount the target volume read-only.
4. Scan files with ClamAV and YARA.
5. Inspect common persistence locations.
6. Calculate hashes and collect findings.
7. Produce a report.
8. Optionally quarantine selected files to writable external storage without automatically deleting evidence.

## Build

See [docs/BUILD.md](docs/BUILD.md).

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Scanning

See [docs/SCANNING.md](docs/SCANNING.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

MIT.
