# Net Tool — IP Conflict Scanner

A lightweight PowerShell tool that scans an IPv4 network range, detects **IP
conflicts** (a single IP answered by more than one device), and prints the
**conflicted MAC addresses**.

Works on **Windows PowerShell 5.1** with built-in cmdlets and native Windows
tools only. No admin rights and no third-party modules required.

## What is an IP conflict?

An IP conflict occurs when two devices on the same network are configured with the
same IP address. This scanner detects it by watching the ARP/neighbor cache: it
pings each host and reads the MAC address that answers. If an IP ever maps to more
than one distinct MAC address across repeated probes, that IP is reported as
conflicted.

> **Note:** Without admin rights you cannot flush the ARP cache, so detection is
> probabilistic — it relies on repeated probes catching switches when the two
> devices alternate answering. More rounds (`-Rounds`) also increase confidence.

## Requirements

- Windows
- Windows PowerShell 5.1 (built in)
- No admin rights needed
- No third-party modules
- Network connectivity

## Usage

```
.\Scan-IPConflicts.ps1
```

If you run it with no arguments, it prompts for the network range:

```
Enter the network range to scan.
  Examples: 192.168.1.0/24 | 192.168.1.1-192.168.1.254 | 192.168.1.5
Range:
```

Accepted range formats:

| Format          | Example                            |
|-----------------|------------------------------------|
| CIDR            | `192.168.1.0/24`                  |
| Start–End       | `192.168.1.1-192.168.1.254`       |
| Single IP       | `192.168.1.5`                     |

### Parameters

| Parameter    | Default | Description                                            |
|--------------|---------|--------------------------------------------------------|
| `Target`     | *prompt*| Network range (CIDR, start–end, or single IP)          |
| `Rounds`     | `3`     | Times each IP is probed (more = better conflict catch) |
| `TimeoutMs`  | `250`   | Per-probe ICMP timeout (milliseconds)                  |
| `NoPrompt`   | –       | Don't prompt; still required if `Target` is supplied   |

### Examples

```
.\Scan-IPConflicts.ps1 -Target 192.168.1.0/24
.\Scan-IPConflicts.ps1 -Target 192.168.1.1-192.168.1.254 -Rounds 5
.\Scan-IPConflicts.ps1 -Target 10.0.0.1
```

## Output

While scanning, a live progress bar is shown via `Write-Progress`. On completion
the console prints a summary and lists each conflicted IP with its MAC addresses:

```
==============================
          RESULTS
==============================
Total hosts scanned : 254
Hosts responding    : 42
IP conflicts found  : 1

The following IP(s) are CONFLICTED (multiple MAC addresses):

  IP: 192.168.1.20   MACs: 2
        00:1A:2B:3C:4D:5E
        10:20:30:40:50:60
```

The script also emits result objects (with `IP`, `MACCount`, `Conflicted`, `MACs`)
so the output can be piped to other commands.

## Development

See `AGENTS.md` for agent/contributor guidance, and run:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ScanIPConflicts.ps1
```

to run the offline sanity checks.
