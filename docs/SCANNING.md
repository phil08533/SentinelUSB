# Scanning Design

## MVP

The scanner should:

1. Detect block devices.
2. Identify Windows volumes.
3. Mount the selected volume read-only.
4. Run ClamAV against selected paths.
5. Run YARA rules against selected paths.
6. Hash relevant findings with SHA-256.
7. Inspect common persistence locations.
8. Write JSON and HTML reports.

## Detection philosophy

SentinelUSB is an analysis/rescue environment, not a claim of perfect malware detection. Results should distinguish:

- **Known threat:** a detection from an established signature/rule.
- **Suspicious:** a heuristic or persistence finding requiring human review.
- **Informational:** system artifacts useful during investigation.

The application should never present a suspicious item as confirmed malware without an appropriate detection basis.

## Read-only behavior

Scanning should not modify the target Windows filesystem. If the volume is hibernated, dirty, encrypted, inaccessible, or otherwise unsafe to mount, SentinelUSB should report the condition rather than silently forcing a write-capable mount.

## Quarantine

Quarantine is a later feature. It should be opt-in, store files outside the target volume, calculate hashes before and after copying, and record the original path.

## Safe testing

The EICAR test file is the primary antivirus integration test. Unit tests should use synthetic fixtures and benign files.
