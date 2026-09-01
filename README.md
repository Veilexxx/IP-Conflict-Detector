# IP Conflict Detector

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
>
> **Cannot test your own IP:** a conflict on the scanning machine's own address
> is undetectable from that machine (pinging yourself never touches the network
> and your own IP never appears in the ARP cache). The scanner skips its own IPs
> with a warning — run the scan from a *different* device to test them.

## Requirements

- Windows
- Windows PowerShell 5.1 (built in)
- No admin rights needed (but running as Administrator gives more reliable conflict detection — see below)
- No third-party modules
- Network connectivity

## First run: execution policy

Windows PowerShell ships with the `Restricted` execution policy, which blocks **all**
scripts from running (even as Administrator). You'll see an error like:

> File ...\Scan-IPConflicts.ps1 cannot be loaded because running scripts is
> disabled on this system.

Pick **one** of the following:

**Option A — Bypass just for this run** (recommended, no system change):

```
powershell -ExecutionPolicy Bypass -File .\Scan-IPConflicts.ps1 -Target 192.168.1.0/24
```

**Option B — Allow local scripts for your user, permanently:**

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

(This affects only your account and only local scripts; signed/remote scripts are
still validated. Run it once, then launch the script normally.)

> If you downloaded the script from the web, PowerShell may also mark it as
> "blocked". Unblock it once with:
>
> ```
> Unblock-File -Path .\Scan-IPConflicts.ps1
> ```

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

| Parameter       | Default | Description                                                                 |
|-----------------|---------|-----------------------------------------------------------------------------|
| `Target`        | *prompt*| Network range (CIDR, start–end, or single IP)                               |
| `Rounds`        | `5`     | Times each IP is re-probed; each round re-resolves ARP, catching MAC flips   |
| `TimeoutMs`     | `250`   | Per-probe ICMP timeout (milliseconds)                                        |
| `RoundDelaySec` | `2`     | Seconds to wait between rounds so the ARP entry can re-resolve               |
| `NoPrompt`      | –       | Don't prompt; still required if `Target` is supplied                         |

### Examples

```
.\Scan-IPConflicts.ps1 -Target 192.168.1.0/24
.\Scan-IPConflicts.ps1 -Target 192.168.1.1-192.168.1.254 -Rounds 5
.\Scan-IPConflicts.ps1 -Target 10.0.0.1
.\Scan-IPConflicts.ps1 -Target 192.168.1.0/24 -Rounds 8 -RoundDelaySec 3
```

### Reliability & Administrator rights

Windows holds only **one MAC per IP** in the ARP cache at a time, so an IP conflict
is only seen when the cache *flips* to the second device between probe rounds.

- **Run as Administrator** for the most reliable detection: the scan flushes each
  ARP entry (`arp -d <ip>`) before re-resolving, so both MACs are observed.
- **Without admin**, the scan cannot flush ARP, so it waits `-RoundDelaySec`
  between rounds and relies on the entry aging out. Windows keeps an entry for
  15–45 s, so short delays rarely expose a MAC flip. Detection is then
  *probabilistic* — if you get "No IP conflicts detected" with admin unavailable,
  re-run with e.g. `-Rounds 6 -RoundDelaySec 45`.
- **Conflicts on your own IP are not detectable from this machine.** If the
  conflicted address is assigned to the PC running the scan, that PC answers its
  own pings via loopback and never ARPs for itself. The scanner detects this,
  skips its own addresses, and warns you to run the scan from another device.

> **Enabling admin still requires the execution-policy step above.** To run as
> Administrator with the policy bypass in one line, right-click the PowerShell icon
> → *Run as Administrator*, then:
>
> ```
> powershell -ExecutionPolicy Bypass -File .\Scan-IPConflicts.ps1 -Target 192.168.1.0/24
> ```
>
> (Or set `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`
> once, then launch normally from an elevated shell.)


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
