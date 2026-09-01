# AGENTS.md

Guidance for AI agents / contributors working in this repository. Read this
before changing or extending the tool.

## Project purpose

`Scan-IPConflicts.ps1` scans an IPv4 network range, detects **IP conflicts**
(one IP answered by more than one device), and prints the conflicted **MAC
addresses**. It prompts for the range (or accepts it as an argument), and shows a
live progress bar while scanning.

## Hard runtime constraints (IMPORTANT)

The tool runs on this machine and must keep working here. These constraints are
NOT optional:

- **Windows PowerShell 5.1 only.** There is no `pwsh`, no Python, no Node. Do not
  rewrite in another language or use PS 7+ cmdlets.
- **No admin rights.** The scanner runs as a standard user. Do not rely on
  admin-only operations.
- **No third-party modules.** Use only built-in PowerShell cmdlets and native
  Windows tools.
- Language/detection choices were confirmed with the user: **PowerShell script**,
  **ARP-cache multi-MAC** detection, **console-only output**.

## How it works / detection strategy

An IP conflict is detected via **MAC flip-flopping** in the ARP/neighbor cache:

1. Parse the target range (CIDR, start–end, or single IP) into a list of IPs.
2. Reachability sweep: `System.Net.NetworkInformation.Ping.SendPingAsync` fired
   for every IP and awaited via `Task.GetAwaiter().GetResult()` (the .NET thread
   pool does the concurrency). Live hosts are collected.
3. Conflict probe: for `-Rounds` rounds, **re-ARP each live host** (and wait
   `-RoundDelaySec` between rounds so the entry can re-resolve), then read the MAC
   from the neighbor cache (`Get-NetNeighbor`, falling back to `arp -a`).
4. Group `IP -> set<MAC>`. Any IP with >1 distinct MAC is a **conflict**.

Because the OS keeps a single MAC per IP in the ARP cache, a conflict is only
exposed when the cache **flips** to the second device between observations. The
scan forces that flip by re-ARP'ing each target every round. With Administrator
rights it flushes each ARP entry (`arp -d <ip>`) first — fully reliable. Without
admin it cannot flush, so it relies on the cached entry aging out between rounds;
this is *probabilistic* and may need more `-Rounds` / bigger `-RoundDelaySec`.
This limitation is documented in the output (a "run as Administrator" tip) and
expected.

**Own-IP exclusion:** a conflict on the scanning machine's OWN address is
undetectable from that machine — pinging yourself is loopback (never touches the
wire) and Windows never puts your own IP in the ARP/neighbor cache. Reachable
IPs that match a local interface address are therefore skipped before probing,
with a loud warning telling the user to scan from a different device.

## File layout

- `Scan-IPConflicts.ps1` — the single-file scanner (no external deps).
- `AGENTS.md` — this file.
- `README.md` — human usage docs.
- `tests/Test-ScanIPConflicts.ps1` — self-contained sanity checks for the pure
  parsing/grouping logic (no live network required).

## Required checks before finishing a change

- [ ] Run a syntax parse: `powershell -NoProfile -Command "& { $null = [scriptblock]::Create((Get-Content -Raw .\Scan-IPConflicts.ps1)) }"` (or invoke `[System.Management.Automation.Language.Parser]::ParseFile`).
- [ ] Run the tests: `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ScanIPConflicts.ps1`
- [ ] Confirm it still runs as a standard user (no admin) and emits progress.

## Running / execution policy

By default Windows PowerShell's `Restricted` execution policy blocks *all* scripts,
even from an elevated (Administrator) shell — the symptom is
"cannot be loaded because running scripts is disabled on this system." Contributors
should launch with `powershell -ExecutionPolicy Bypass -File .\Scan-IPConflicts.ps1`
(or `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once). The
test command above already passes `-ExecutionPolicy Bypass`.

## Testing without a network

The reachable-host sweep and conflict probe require a live network. The test file
therefore only exercises deterministic, self-contained logic that must be kept
isolatable:

- `Get-IPRange` (range parsing / expansion) — currently a private function. If you
  change it, keep the range-expansion test (CIDR, start–end, single IP) passing.
- MAC normalization: a `00-1A-2B-3C-4D-5E` ARP table value becomes `00:1A:2B:3C:4D:5E`.
- Conflict grouping: building `IP -> set<MAC>` and flagging >1 MAC.

To keep logic testable, prefer pure functions (parse, normalize, group) in the
main script, and keep network I/O in separate functions.

## Conventions

- `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'` at top.
- Uppercase MACs with `:` separators everywhere in the report.
- Use `Write-Progress` for live progress; `Write-Host` for console output.
- Avoid assuming which network interface is active; the tool scans whatever range
  the user provides.
- Add a `#Requires -Version 5.1` header and keep the script single-file.

## Gotchas

- `arp -d` **exits 0 even when the deletion fails** ("The ARP entry deletion
  failed: The requested operation requires elevation." goes to stderr). Never
  gate flush-success on `$LASTEXITCODE` or try/catch — check elevation directly
  via `[Security.Principal.WindowsPrincipal]`.
- `Get-NetNeighbor` may return several rows; always take the first *Reachable /
  Stale* row and ignore the all-zero MAC (`00-00-00-00-00-00`).
- ARP entries can be `Incomplete`; treat those as "no MAC" and keep probing.
- Ping concurrently via `SendPingAsync` + `Task.GetAwaiter().GetResult()`. Do NOT
  fall back to `RunspacePool`/`[RunspaceFactory]` — per-runspace startup overhead
  makes it appear to hang on ranges larger than a few dozen IPs.
- Cap the range at 65536 IPs. `Get-IPRange` expands the whole range up front, so
  huge prefixes (e.g. `/8`) must be rejected before enumeration.
- Some hosts block ICMP; a non-responding host is not necessarily down (it won't
  be in the conflict report).
