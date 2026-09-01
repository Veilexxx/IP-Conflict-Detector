#Requires -Version 5.1
<#
.SYNOPSIS
    Scans an IPv4 network range for IP conflicts and displays the conflicted
    MAC addresses.

.DESCRIPTION
    Sends a probe (ICMP ping) to every host in a given IP range, then reads the
    local ARP/neighbor cache to associate each responding IP with a MAC address.
    Because IP conflicts manifest as two devices answering for the same IP, the
    tool probes each IP several times (rounds) across which the resolved MAC can
    flip. Any IP observed to map to MORE THAN ONE distinct MAC address is flagged
    as a conflict and its conflicted MAC addresses are listed.

    Runs on Windows PowerShell 5.1 using only built-in cmdlets and native tools
    (Test-Connection, ping, arp, Get-NetNeighbor). No admin rights required for a
    best-effort scan; note that without admin you cannot flush the ARP cache, so
    conflict detection relies on repeated probing catching MAC flip-flopping.

    LIMITATION: a conflict on THIS machine's own IP cannot be detected from this
    machine — pinging yourself is loopback-only and your own IP never appears in
    the ARP cache. Such addresses are skipped with a warning; scan from a
    different device to test them.

.PARAMETER Target
    The network range to scan. Accepts either form:
      * CIDR:           192.168.1.0/24
      * Start-End:      192.168.1.1-192.168.1.254
      * Single IP:      192.168.1.5
    If omitted the user is prompted interactively.

.PARAMETER Rounds
    How many times each IP is probed. More rounds increase the chance of catching
    an IP that alternates MAC addresses (the signature of a conflict). Default 3.

.PARAMETER TimeoutMs
    Per-probe ICMP timeout in milliseconds. Default 250.

.PARAMETER RoundDelaySec
    Seconds to wait between probe rounds. Between rounds the script re-ARP's each
    target so the neighbour cache can re-resolve; this is what exposes an IP whose
    MAC flips between two devices (an IP conflict). A non-zero delay is important
    because Windows keeps an ARP entry cached, so a too-fast scan only ever sees
    one MAC. Default 2.

.PARAMETER NoPrompt
    Do not prompt for input. NoPrompt is implicit when a Target is supplied.
    This parameter prevents Get-IPConflicts from blocking on a prompt.

.OUTPUTS
    PSCustomObject with properties: IP, MACCount, Conflicted (bool), MACs (string[])
    The console view shows the conflict summary; returned objects always include.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target,

    [ValidateRange(1, 60)]
    [int]$Rounds = 5,

    [ValidateRange(50, 5000)]
    [int]$TimeoutMs = 250,

    [ValidateRange(0, 60)]
    [int]$RoundDelaySec = 2,

    [switch]$NoPrompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function ConvertTo-IPAddress {
    param([string]$Text)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Text, [ref]$ip)) {
        return $ip
    }
    return $null
}

function ConvertIPTo-UInt32 {
    param([System.Net.IPAddress]$IP)
    $bytes = $IP.GetAddressBytes()
    if ($bytes.Length -ne 4) { throw "Only IPv4 addresses are supported." }
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    [uint32][BitConverter]::ToUInt32($bytes, 0)
}

function ConvertUInt32-ToIP {
    param([uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    [System.Net.IPAddress]::new($bytes)
}

function Get-IPRange {
    param([string]$InputText)

    $inputText = $InputText.Trim()

    # Single IP
    if ($null -ne (ConvertTo-IPAddress $inputText)) {
        $ip = ConvertIPTo-UInt32 (ConvertTo-IPAddress $inputText)
        $list = [System.Collections.Generic.List[uint32]]::new()
        $list.Add($ip)
        return ,$list
    }

    # Start-End
    if ($inputText -match '^\s*(.+?)\s*[-–]\s*(.+?)\s*$') {
        $start = ConvertTo-IPAddress $matches[1]
        $end   = ConvertTo-IPAddress $matches[2]
        if ($null -eq $start -or $null -eq $end) {
            throw "Invalid start/end IP range: '$InputText'"
        }
        $startV = ConvertIPTo-UInt32 $start
        $endV   = ConvertIPTo-UInt32 $end
        [Int64]$count = $endV - $startV + 1
        if ($count -le 0) {
            throw "End of range is before the start: '$InputText'"
        }
        if ($count -gt 65536) {
            throw "Range of $count IPs is too large (max 65536)."
        }
        $list = [System.Collections.Generic.List[uint32]]::new()
        for ([uint32]$v = $startV; $v -le $endV; $v++) {
            $list.Add($v)
        }
        return ,$list
    }

    # CIDR
    if ($inputText -match '^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*/\s*(\d{1,2})\s*$') {
        $base = ConvertTo-IPAddress $matches[1]
        $prefix = [int]$matches[2]
        if ($null -eq $base -or $prefix -gt 32) {
            throw "Invalid CIDR: '$InputText'"
        }
        # Compute mask in Int64 to avoid uint32 overflow on shift.
        $mask = if ($prefix -eq 0) { [Int64]0 } else { ([Int64]0xFFFFFFFF -shl (32 - $prefix)) -band [Int64]0xFFFFFFFF }
        $baseV = [Int64](ConvertIPTo-UInt32 $base)
        $netV = $baseV -band $mask
        $broadcastV = $netV -bor ((-bnot $mask) -band [Int64]0xFFFFFFFF)
        [Int64]$count = $broadcastV - $netV + 1
        if ($count -gt 65536) {
            throw "Range of $count IPs is too large (max 65536)."
        }
        $list = [System.Collections.Generic.List[uint32]]::new()
        for ([Int64]$v = $netV; $v -le $broadcastV; $v++) {
            $list.Add([uint32]$v)
        }
        return ,$list
    }

    throw "Could not parse range. Use CIDR (192.168.1.0/24), start-end (192.168.1.1-192.168.1.254), or a single IP."
}

function Get-ReachableIPs {
    param(
        [System.Collections.Generic.List[uint32]]$IPs,
        [int]$TimeoutMs
    )

    # Asynchronous ICMP sweep using Ping.SendPingAsync over the .NET thread pool.
    # This avoids the heavy runspace-per-host overhead and is both fast and
    # deadlock-free for large ranges.
    $results = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $pings = [System.Collections.Generic.List[System.Net.NetworkInformation.Ping]]::new()
    $tasks = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
    $addresses = [System.Collections.Generic.List[string]]::new()

    foreach ($v in $IPs) {
        $ip = (ConvertUInt32-ToIP $v).ToString()
        $ping = New-Object System.Net.NetworkInformation.Ping
        [void]$pings.Add($ping)
        [void]$addresses.Add($ip)
        [void]$tasks.Add($ping.SendPingAsync($ip, $TimeoutMs))
    }

    # Wait for every task to finish, swallowing individual faults (e.g. host
    # unreachable, network errors) so one bad host cannot abort the sweep.
    foreach ($task in $tasks) {
        try { $null = $task.GetAwaiter().GetResult() } catch { # expected per-host error
        }
    }

    for ($i = 0; $i -lt $tasks.Count; $i++) {
        try {
            $reply = $tasks[$i].Result
            if ($reply.Status -eq 'Success') {
                [void]$results.Add($addresses[$i])
            }
        } catch {
            # Noop: ignore hosts whose probe faulted.
        }
    }

    foreach ($ping in $pings) { $ping.Dispose() }

    return ,@($results)
}

function Get-LocalIPv4Addresses {
    # All IPv4 addresses assigned to this machine, across every interface.
    # Pure .NET: works as a standard user and without the NetTCPIP module.
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
        Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
        ForEach-Object { $_.Address.ToString() }
}

function Get-MACAddress {
    param([string]$IP)
    try {
        $neighbor = Get-NetNeighbor -IPAddress $IP -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.State -in @('Reachable', 'Stale') } |
            Select-Object -First 1
        if ($neighbor -and $neighbor.LinkLayerAddress -ne '00-00-00-00-00-00') {
            return (($neighbor.LinkLayerAddress -replace '[-]', ':').ToUpper())
        }
    } catch {
        # Fall through to arp table
    }
    # Fallback: ARP table
    try {
        $line = arp -a $IP 2>$null | Select-String -Pattern '^\s*\d+\.\d+\.\d+\.\d+\s+(\S+)' |
            Select-Object -First 1
        if ($line) {
            $mac = [regex]::Match($line.Line, '\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+').Groups[1].Value
            if ($mac) { return (($mac -replace '[-]', ':').ToUpper()) }
        }
    } catch {
        return $null
    }
    return $null
}

function New-ConflictReport {
    param([string[]]$IPs, [int]$Rounds, [int]$RoundDelaySec)

    $ipMacs = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Collections.Generic.HashSet[string]]]::new()
    # arp.exe exits 0 even when the deletion fails ("requires elevation" goes to
    # stderr), so gate the flush on a real elevation check instead of the result.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $flushedAny = $false

    foreach ($round in 1..$Rounds) {
        # Force the neighbour cache to re-resolve this round so a flapping MAC is
        # exposed. When running as Administrator, flush each ARP entry directly
        # (reliable). Without admin the flush is impossible, so we rely on the
        # delay letting the cached entry age out and the OS re-ARP naturally.
        if ($round -gt 1) {
            if ($RoundDelaySec -gt 0) { Start-Sleep -Seconds $RoundDelaySec }
            if ($isAdmin) {
                foreach ($ip in $IPs) {
                    try {
                        arp -d $ip 2>$null | Out-Null
                    } catch {
                        # Entry absent or deletion refused: ignore.
                    }
                }
                $flushedAny = $true
            }
        }

        Write-Progress -Activity "Probing network (round $round of $Rounds)" `
            -Status "Sending probes and collecting ARP entries..." `
            -PercentComplete (($round - 1) / $Rounds * 100)

        # Refresh/force ARP resolution for every reachable host in parallel.
        $pings = [System.Collections.Generic.List[System.Net.NetworkInformation.Ping]]::new()
        $tasks = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
        foreach ($ip in $IPs) {
            $ping = New-Object System.Net.NetworkInformation.Ping
            [void]$pings.Add($ping)
            [void]$tasks.Add($ping.SendPingAsync($ip, 300))
        }
        foreach ($task in $tasks) {
            try { $null = $task.GetAwaiter().GetResult() } catch { # Noop
            }
        }
        foreach ($ping in $pings) { $ping.Dispose() }

        foreach ($ip in $IPs) {
            $mac = Get-MACAddress $ip
            if ($mac) {
                if (-not $ipMacs.ContainsKey($ip)) {
                    $ipMacs.TryAdd($ip, [System.Collections.Generic.HashSet[string]]::new()) | Out-Null
                }
                $set = $null
                if ($ipMacs.TryGetValue($ip, [ref]$set)) {
                    [void]$set.Add($mac)
                }
            }
        }
    }
    Write-Progress -Activity "Probing network" -Completed
    $script:ArpFlushActive = $flushedAny

    $report = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $ipMacs.Keys) {
        $set = $null
        [void]$ipMacs.TryGetValue($key, [ref]$set)
        $macs = @($set)
        $report.Add([pscustomobject]@{
                IP         = $key
                MACCount   = $macs.Count
                Conflicted = ($macs.Count -gt 1)
                MACs       = $macs
            })
    }
    return ,$report
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "              Network IP Conflict Scanner (PowerShell)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# Determine the target range
$rangeText = $Target
if (-not $rangeText) {
    if ($NoPrompt -or -not [Environment]::UserInteractive) {
        throw "No target range provided. Use: .\Scan-IPConflicts.ps1 -Target 192.168.1.0/24"
    }
    Write-Host "Enter the network range to scan." -ForegroundColor Green
    Write-Host "  Examples: 192.168.1.0/24 | 192.168.1.1-192.168.1.254 | 192.168.1.5" -ForegroundColor DarkGray
    $rangeText = Read-Host "Range"
}

# Expand and sanity-check
$range = $null
try {
    $range = Get-IPRange $rangeText
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($range.Count -eq 0) {
    Write-Host "ERROR: range is empty." -ForegroundColor Red
    exit 1
}

if ($range.Count -gt 65536) {
    Write-Host "ERROR: range of $($range.Count) IPs is too large (max 65536)." -ForegroundColor Red
    exit 1
}

Write-Host "Range: $rangeText  =>  $($range.Count) IPs" -ForegroundColor Yellow
Write-Host "Rounds: $Rounds | Timeout: $TimeoutMs ms" -ForegroundColor DarkGray
Write-Host ""

# Find reachable hosts (progress: percent complete via concurrent dictionary count)
Write-Host "Discovering reachable hosts..." -ForegroundColor Green
$ticks = [System.Diagnostics.Stopwatch]::StartNew()
$reachable = Get-ReachableIPs -IPs $range -TimeoutMs $TimeoutMs
$ticks.Stop()
Write-Host ("Found {0} reachable host(s) in {1:n2} s" -f $reachable.Count, $ticks.Elapsed.TotalSeconds) -ForegroundColor Green
Write-Host ""

if ($reachable.Count -eq 0) {
    Write-Host "No reachable hosts found; cannot evaluate conflicts." -ForegroundColor Yellow
    exit 0
}

# Separate out this machine's own IPs. A conflict on your OWN address is
# undetectable from the same machine: pinging yourself is answered by loopback
# (the packet never reaches the other device) and your own IP never appears in
# the ARP/neighbor cache, so no MAC is ever observed for it.
$localIPs = @(Get-LocalIPv4Addresses)
$ownIPs = @($reachable | Where-Object { $localIPs -contains $_ })
$probeIPs = @($reachable | Where-Object { $localIPs -notcontains $_ })

if ($ownIPs.Count -gt 0) {
    Write-Host "WARNING: these reachable IP(s) belong to THIS machine and were skipped:" -ForegroundColor Yellow
    foreach ($ip in $ownIPs) {
        Write-Host "    $ip" -ForegroundColor Yellow
    }
    Write-Host "  A conflict on your own IP CANNOT be detected from this machine. Run this" -ForegroundColor Yellow
    Write-Host "  scan from a DIFFERENT device on the same network to test that address." -ForegroundColor Yellow
    Write-Host ""
}

if ($probeIPs.Count -eq 0) {
    Write-Host "No remote hosts left to probe; cannot evaluate conflicts." -ForegroundColor Yellow
    exit 0
}

# Probe reachable hosts for MAC conflict detection
Write-Host "Checking reachable hosts for IP conflicts..." -ForegroundColor Green
$report = New-ConflictReport -IPs $probeIPs -Rounds $Rounds -RoundDelaySec $RoundDelaySec

$conflicts = @($report | Where-Object { $_.Conflicted })
$clean = @($report | Where-Object { -not $_.Conflicted })

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "                             RESULTS" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ("Total hosts scanned : {0}" -f $reachable.Count) -ForegroundColor Yellow
if ($ownIPs.Count -gt 0) {
    Write-Host ("Skipped (this PC)   : {0}" -f $ownIPs.Count) -ForegroundColor Yellow
}
Write-Host ("Hosts responding    : {0}" -f $report.Count) -ForegroundColor Yellow
Write-Host ("IP conflicts found  : {0}" -f $conflicts.Count) -ForegroundColor $(if ($conflicts.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host ""

if ($conflicts.Count -gt 0) {
    Write-Host "The following IP(s) are CONFLICTED (multiple MAC addresses):" -ForegroundColor Red
    foreach ($c in $conflicts) {
        Write-Host ""
        Write-Host ("  IP: {0}   MACs: {1}" -f $c.IP, $c.MACCount) -ForegroundColor Red
        foreach ($m in $c.MACs) {
            Write-Host ("        {0}" -f $m) -ForegroundColor White
        }
    }
} else {
    Write-Host "No IP conflicts detected." -ForegroundColor Green
    if (-not $script:ArpFlushActive) {
        Write-Host ""
        Write-Host "Tip: ARP flushing was unavailable (not running as Administrator), so conflict" -ForegroundColor DarkGray
        Write-Host "detection relied on the neighbour cache aging out between rounds. Windows" -ForegroundColor DarkGray
        Write-Host "keeps an ARP entry for 15-45 s, so short delays rarely expose a MAC flip." -ForegroundColor DarkGray
        Write-Host "Re-run as Administrator, or with e.g. -Rounds 6 -RoundDelaySec 45, for" -ForegroundColor DarkGray
        Write-Host "better odds of catching an IP whose MAC only flips occasionally." -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host ("Scan complete in {0:n2} s." -f $ticks.Elapsed.TotalSeconds) -ForegroundColor DarkGray

# Hold the window open so results remain readable when double-clicked from
# Explorer. Skips when -NoPrompt is set or when output is redirected (non-interactive).
if (-not $NoPrompt -and [Environment]::UserInteractive) {
    Write-Host ""
    Write-Host "Press Enter to exit..." -ForegroundColor DarkGray
    try { $null = Read-Host } catch { }
}

# Always emit objects so automation can consume results
return $report
