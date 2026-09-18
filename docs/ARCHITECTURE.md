# Architecture

## Overview

```
USB
 |
 v
SentinelUSB Live Linux
 |
 +-- CLI
 |
 +-- Lightweight GUI
 |
 +-- Storage Manager
 |     +-- Drive detection
 |     +-- Read-only Windows mounting
 |
 +-- Scanner
 |     +-- ClamAV
 |     +-- YARA
 |     +-- SHA-256 hashing
 |
 +-- Persistence Analyzer
 |     +-- Startup folders
 |     +-- Services
 |     +-- Scheduled tasks
 |     +-- Registry persistence (later milestone)
 |
 +-- Quarantine
 |
 +-- Reporting
       +-- HTML
       +-- JSON
```

## Separation of concerns

The scanning engine should not depend on the graphical interface. This allows:

- command-line use over a local terminal or future remote console
- easier automated testing
- a smaller base image
- a GUI that can be replaced without rewriting detection logic

The GUI should call the same scanner APIs used by the CLI.

## Safety model

Target volumes are read-only by default.

Actions that modify files must be explicit and should require confirmation. Quarantine should copy evidence to a separate writable location and preserve the original hash and metadata in the report.

## Persistence

Filesystem persistence checks come first. Offline Windows registry analysis will be added after the basic scanner is stable.
