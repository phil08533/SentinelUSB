# Persistent report storage

SentinelUSB keeps investigation reports separate from the read-only live system.

## Recommended layout

Use a writable partition on the same USB drive labeled exactly:

`SENTINELDATA`

SentinelUSB looks for:

`/dev/disk/by-label/SENTINELDATA`

and mounts it at:

`/mnt/sentinel-data`

Reports are then written to:

`/mnt/sentinel-data/Reports/`

Each scan gets its own timestamped directory containing:

- `report.html`
- `report.json`
- `clamav.log`

## Why a separate partition?

The bootable ISO filesystem is intentionally read-only. Automatically repartitioning the user's USB would be destructive and unsafe, so SentinelUSB never repartitions a drive by itself.

Create the writable partition once, then SentinelUSB can reuse it on every boot.

## Creating it

On a Linux computer, identify the USB carefully with `lsblk`. If you already have unallocated space on the USB, create a filesystem there and label it `SENTINELDATA`.

Example for a partition you have positively identified:

```bash
sudo mkfs.ext4 -L SENTINELDATA /dev/sdX2
```

**This erases the selected partition. Never substitute a device path unless you have verified it.**

Alternatively, create and format the partition with a graphical partition manager.

## Checking it

Boot SentinelUSB and run:

```text
sentinel> storage
```

A successful setup shows the device, mountpoint, and report directory.

If the partition is missing, scans still work, but reports fall back to the live environment and should be copied out before rebooting.

## Safety

SentinelUSB does not automatically repartition, format, or delete files. The target operating-system volume remains read-only during scanning. The SENTINELDATA partition is the only storage SentinelUSB mounts read-write, and only for reports.
