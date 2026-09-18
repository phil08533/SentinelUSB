# Roadmap

## Phase 0 — Foundation
- [x] Project repository
- [x] Landing page
- [x] Architecture documentation
- [x] Threat model
- [x] Build plan
- [ ] Initial live-build configuration

## Phase 1 — Bootable scanner
- [ ] Build minimal Debian live ISO
- [ ] Boot successfully in VM
- [ ] Detect disks
- [ ] Detect Windows volumes
- [ ] Read-only mounting
- [ ] Basic CLI

## Phase 2 — Detection
- [ ] ClamAV integration
- [ ] YARA integration
- [ ] SHA-256 hashing
- [ ] EICAR test
- [ ] JSON reports
- [ ] HTML reports

## Phase 3 — Windows persistence
- [ ] Startup folders
- [ ] Scheduled task artifacts
- [ ] Service artifacts
- [ ] Common Run/RunOnce locations
- [ ] Offline registry parsing

## Phase 4 — Interface
- [ ] Lightweight GUI
- [ ] Drive selection
- [ ] Scan progress
- [ ] Findings viewer
- [ ] Report export

## Phase 5 — Release engineering
- [ ] ISO checksum generation
- [ ] Automated ISO builds
- [ ] Reproducible build documentation
- [ ] Small-image optimization
