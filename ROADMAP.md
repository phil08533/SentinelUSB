# Roadmap

## Phase 0 — Foundation
- [x] Project repository
- [x] Landing page
- [x] Architecture documentation
- [x] Threat model
- [x] Build plan
- [x] Initial live-build configuration

## Phase 1 — Bootable scanner
- [x] Build minimal Debian live ISO
- [x] Bootable amd64 image
- [x] Detect disks
- [x] Detect Windows, Linux, and macOS volumes
- [x] Read-only mounting
- [x] Basic CLI

## Phase 2 — Detection
- [x] ClamAV integration
- [x] YARA integration
- [x] SHA-256 hashing
- [ ] EICAR end-to-end test on the built ISO
- [x] JSON reports
- [x] HTML reports
- [x] Offline-capable scanning

## Phase 3 — Persistence
- [x] Windows Startup folders
- [x] Windows scheduled task artifacts
- [x] Windows Run / RunOnce registry locations
- [x] Windows service registry artifacts
- [x] Linux systemd and cron locations
- [x] Linux user startup and SSH authorized_keys checks
- [x] macOS LaunchAgents / LaunchDaemons
- [x] macOS configuration-profile check
- [ ] Broader Windows registry coverage

## Phase 4 — Interface
- [x] Lightweight GUI
- [x] Drive selection
- [x] Scan progress/status
- [x] Findings count and report location
- [x] Report opening
- [x] Terminal workflow with Sentinel ASCII art

## Phase 5 — Report storage
- [x] Persistent SENTINELDATA partition support
- [x] Timestamped report directories
- [x] HTML + JSON + ClamAV log preservation
- [x] Storage status command
- [ ] Test persistence across a real reboot

## Phase 6 — Release engineering
- [x] ISO checksum generation
- [x] Automated ISO builds
- [x] ISO structure verification
- [x] Split artifact packaging
- [x] Build-time Python validation
- [ ] EICAR validation on the released image
- [ ] Final VM / physical-hardware test
- [ ] First public GitHub Release
- [ ] Release screenshots / demo
- [ ] Small-image optimization pass
