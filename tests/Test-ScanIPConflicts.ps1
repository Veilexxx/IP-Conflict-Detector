#Requires -Version 5.1
<#
.SYNOPSIS
    Offline sanity checks for Scan-IPConflicts.ps1.

.DESCRIPTION
    These tests exercise only deterministic, self-contained logic so they can run
    with NO live network. They cover:
      * Get-IPRange: CIDR, start-end, and single-IP expansion.
      * MAC normalization (00-1A-2B-3C-4D-5E -> 00:1A:2B:3C:4D:5E).
      * Conflict grouping: IP -> set<MAC>, flagging any IP with >1 MAC.

    RUN:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ScanIPConflicts.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Pass = 0
$script:Fail = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        $script:Pass++
        Write-Host ("[PASS] {0}" -f $Name) -ForegroundColor Green
    } else {
        $script:Fail++
        Write-Host ("[FAIL] {0}" -f $Name) -ForegroundColor Red
    }
}

function Assert-MacEqual {
    param([string[]]$Actual, [string[]]$Expected, [string]$Name)
    $a = @($Actual) | Sort-Object
    $e = @($Expected) | Sort-Object
    $ok = ($a -join ',') -eq ($e -join ',')
    Assert-True $ok $Name
    if (-not $ok) {
        Write-Host ("       expected: {0}" -f ($e -join ', ')) -ForegroundColor DarkGray
        Write-Host ("       actual:   {0}" -f ($a -join ', ')) -ForegroundColor DarkGray
    }
}

# --- Load the real Get-IPRange function from the main script ------------------
# We parse the script and invoke its Get-IPRange definition directly rather than
# dot-sourcing, so the network/main path is never executed.
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Scan-IPConflicts.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$errors)

if ($errors -and $errors.Count -gt 0) {
    Write-Host "Syntax errors in Scan-IPConflicts.ps1:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host ("  {0}" -f $_.Message) -ForegroundColor Red }
    exit 1
}

$fn = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'Get-IPRange'
    }, $true) | Select-Object -First 1

if (-not $fn) {
    Write-Host "Could not locate Get-IPRange function in the script." -ForegroundColor Red
    exit 1
}

# We execute the function body via its own script block. Provide the convert
# helpers it depends on (they are private functions in the file too).
function ConvertTo-IPAddress {
    param([string]$Text)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Text, [ref]$ip)) { return $ip }
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

# Dot-source the real Get-IPRange definition into this scope so it is callable:
. ([scriptblock]::Create($fn.Extent.Text))

function RangeToStrings {
    param([System.Collections.Generic.List[uint32]]$List)
    @($List | ForEach-Object { (ConvertUInt32-ToIP $_).ToString() })
}

Write-Host ""
Write-Host "--- Range parsing ---" -ForegroundColor Cyan

# CIDR /24 expands to a full /24
$r = & Get-IPRange '192.168.1.0/24'
Assert-True ($r.Count -eq 256) "CIDR /24 expands to 256 IPs (got $($r.Count))"
Assert-True ((RangeToStrings $r)[0] -eq '192.168.1.0') "CIDR /24 first IP is .0"
Assert-True ((RangeToStrings $r)[255] -eq '192.168.1.255') "CIDR /24 last IP is .255"

# Start-End
$r2 = & Get-IPRange '10.0.0.5-10.0.0.9'
Assert-True ($r2.Count -eq 5) "Start-end expands to 5 IPs (got $($r2.Count))"
Assert-MacEqual (RangeToStrings $r2) @('10.0.0.5', '10.0.0.6', '10.0.0.7', '10.0.0.8', '10.0.0.9') "Start-end covers exact range"

# Single IP
$r3 = & Get-IPRange '192.168.1.5'
Assert-True ($r3.Count -eq 1) "Single IP expands to 1 (got $($r3.Count))"
Assert-MacEqual (RangeToStrings $r3) @('192.168.1.5') "Single IP resolves correctly"

# /30 -> 4 IPs (a small /30)
$r4 = & Get-IPRange '172.16.0.4/30'
Assert-True ($r4.Count -eq 4) "CIDR /30 expands to 4 IPs (got $($r4.Count))"
Assert-MacEqual (RangeToStrings $r4) @('172.16.0.4', '172.16.0.5', '172.16.0.6', '172.16.0.7') "CIDR /30 correct IPs"

# Invalid input throws
$threw = $false
try { $null = & Get-IPRange 'not-an-ip' } catch { $threw = $true }
Assert-True $threw "Invalid range input throws"

Write-Host ""
Write-Host "--- MAC normalization ---" -ForegroundColor Cyan

# ARP-style (dash) -> report (colon, uppercase)
$raw = '00-1A-2B-3C-4D-5E'
$norm = (($raw -replace '[-]', ':').ToUpper())
Assert-MacEqual @($norm) @('00:1A:2B:3C:4D:5E') "Dashed MAC normalized to colon, uppercase"

$raw2 = 'aa-bb-cc-dd-ee-ff'
$norm2 = (($raw2 -replace '[-]', ':').ToUpper())
Assert-MacEqual @($norm2) @('AA:BB:CC:DD:EE:FF') "Lowercase MAC uppercased and colonized"

Write-Host ""
Write-Host "--- Conflict grouping ---" -ForegroundColor Cyan

# Simulate the report logic: IP -> set<MAC>, flag >1 MAC.
function New-GroupedReport {
    param(
        [hashtable]$MacsByIp
    )
    $report = New-Object System.Collections.Generic.List[object]
    foreach ($ip in $MacsByIp.Keys) {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($m in $MacsByIp[$ip]) { [void]$set.Add($m) }
        $macs = @($set)
        $report.Add([pscustomobject]@{
                IP         = $ip
                MACCount   = $macs.Count
                Conflicted = ($macs.Count -gt 1)
                MACs       = $macs
            })
    }
    return $report
}

$data = @{
    '192.168.1.10' = @('00:AA:00:AA:00:AA', '00:BB:00:BB:00:BB')  # conflict
    '192.168.1.20' = @('00:CC:00:CC:00:CC')                        # clean
}
$rep = New-GroupedReport $data

$conflicted = @($rep | Where-Object { $_.Conflicted })
$clean = @($rep | Where-Object { -not $_.Conflicted })

Assert-True ($conflicted.Count -eq 1) "One IP flagged as conflicted"
Assert-True ($conflicted[0].IP -eq '192.168.1.10') "Conflicted IP is 192.168.1.10"
Assert-True ($conflicted[0].MACCount -eq 2) "Conflicted IP has 2 MACs"
Assert-MacEqual $conflicted[0].MACs @('00:AA:00:AA:00:AA', '00:BB:00:BB:00:BB') "Conflicted MACs listed"
Assert-True ($clean.Count -eq 1) "One IP clean"
Assert-True (-not $clean[0].Conflicted) "Clean IP not flagged"

Write-Host ""
Write-Host ("==== RESULTS: {0} passed, {1} failed ====" -f $script:Pass, $script:Fail) -ForegroundColor Cyan
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
