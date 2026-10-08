<#
.SYNOPSIS
    Audits how a Windows device is licensed and whether a reimage will lose activation.

.DESCRIPTION
    Read-only. Collects hardware details, the firmware (OEM) product key, the installed
    product key decoded from the registry, the active license channel, and the edition,
    then prints a VERDICT line describing reimage risk.

    The only things written to disk are a copy of the output (see -OutFile) and, optionally,
    a watcher task (see -WatchReenroll). The output always includes a "Leftovers" line that
    reports any files or tasks left behind by an earlier deployment.

.PARAMETER OutFile
    Where to save a copy of the output. Default: C:\ProgramData\LicenseAudit\LicenseAudit.txt
    Useful as a detection file when deploying through an MDM "app" item.

.PARAMETER WatchReenroll
    Registers a SYSTEM scheduled task ("LicenseAudit-ReenrollWatch") that runs every 15 minutes.
    If the device's MDM identity changes (the device was re-enrolled into a new record), it deletes
    the output file. Deployed as an MDM app with a file detection rule and continuous enforcement,
    this makes the MDM re-run the audit so the result shows on the new device record.

.PARAMETER RefreshDays
    With -WatchReenroll: the watcher also deletes the output file when it is older than this
    many days, so the audit re-runs and the result stays current. 0 turns this off. Default: 7.

    The watcher removes itself if the output file stays missing for 24 hours, which means the
    MDM no longer deploys the audit. This cleans up devices even if the MDM has no uninstall step.

.PARAMETER Cleanup
    Remove leftovers from an earlier app-style deployment (the watcher task, its helper files,
    and the default output file) before running. Use it when switching to a script-style
    deployment. Don't use it while the app-style deployment is still assigned.

.PARAMETER IdentityPattern
    Regex matched against certificate subjects in the LocalMachine\My store to find the MDM
    agent's device identity. The first capture group is used as the device ID.
    Default matches certificates with a subject like "CN=Agent Identity <GUID>".

.PARAMETER FailOnRisk
    Exit with code 1 when the verdict is anything other than SAFE or DIGITAL LICENSE,
    so at-risk devices show as failed/error in your management tool.

.EXAMPLE
    .\Get-WindowsLicenseAudit.ps1

.EXAMPLE
    .\Get-WindowsLicenseAudit.ps1 -FailOnRisk
#>

[CmdletBinding()]
param(
    [string]$OutFile = "$env:ProgramData\LicenseAudit\LicenseAudit.txt",
    [switch]$WatchReenroll,
    [int]$RefreshDays = 7,
    [switch]$Cleanup,
    [string]$IdentityPattern = 'CN=Agent Identity ([0-9a-fA-F-]{36})',
    [switch]$FailOnRisk
)

$ErrorActionPreference = 'SilentlyContinue'

# Relaunch in 64-bit PowerShell if started from a 32-bit process on 64-bit Windows
if ($env:PROCESSOR_ARCHITEW6432 -and -not [Environment]::Is64BitProcess) {
    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-OutFile', $OutFile)
    if ($WatchReenroll) { $argsList += '-WatchReenroll' }
    if ($Cleanup) { $argsList += '-Cleanup' }
    $argsList += @('-RefreshDays', $RefreshDays, '-IdentityPattern', $IdentityPattern)
    if ($FailOnRisk) { $argsList += '-FailOnRisk' }
    & "$env:WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" @argsList
    exit $LASTEXITCODE
}

New-Item -ItemType Directory -Path (Split-Path $OutFile) -Force | Out-Null

# --- Leftovers from an earlier deployment ---
$appDir   = "$env:ProgramData\LicenseAudit"
$appOut   = Join-Path $appDir 'LicenseAudit.txt'
$taskName = 'LicenseAudit-ReenrollWatch'
$found = @()
if (-not $WatchReenroll -and (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { $found += 'watcher task' }
if (($appOut -ne $OutFile) -and (Test-Path $appOut)) { $found += "old output file ($appOut)" }
if ($found.Count -eq 0) {
    $leftovers = 'none'
} elseif ($Cleanup) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($f in @($appOut, (Join-Path $appDir 'Watch-Reenroll.ps1'), (Join-Path $appDir 'missing-since.txt'))) {
        if ($f -ne $OutFile) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }
    $leftovers = 'removed ' + ($found -join ', ')
} else {
    $leftovers = 'found ' + ($found -join ', ') + ' (run with -Cleanup to remove)'
}

# --- Hardware ---
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os   = Get-CimInstance Win32_OperatingSystem

# --- Firmware (OEM) key embedded by the manufacturer ---
$sls       = Get-CimInstance SoftwareLicensingService
$fwKey     = $sls.OA3xOriginalProductKey
$fwKeyDesc = $sls.OA3xOriginalProductKeyDescription   # e.g. "[4.0] Core OEM:DM" (Core = Home) or "Professional OEM:DM"

# --- Active Windows license ---
$lic = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" |
       Select-Object -First 1
$channel = if ($lic.Description -match '(OEM_DM|OEM_COA_NSLP|OEM_COA_SLP|OEM\w*|RETAIL|VOLUME_MAK|VOLUME_KMSCLIENT|VOLUME_KMS\w*)') { $Matches[1] } else { 'UNKNOWN' }
$status  = switch ($lic.LicenseStatus) {
    0 {'Unlicensed'} 1 {'Licensed'} 2 {'OOB Grace'} 3 {'OOT Grace'}
    4 {'Non-Genuine Grace'} 5 {'Notification'} 6 {'Extended Grace'} default {'Unknown'}
}

# --- Decode installed key from the registry (DigitalProductId) ---
function Get-KeyFromDigitalProductId {
    param([byte[]]$Dpid)
    if (-not $Dpid -or $Dpid.Length -lt 67) { return $null }
    $key    = [int[]]$Dpid[52..66]
    $isWin8 = [math]::Floor($key[14] / 6) -band 1
    $key[14] = ($key[14] -band 0xF7) -bor (($isWin8 -band 2) * 4)
    $chars = 'BCDFGHJKMPQRTVWXY2346789'
    $out  = ''
    $last = 0
    for ($i = 24; $i -ge 0; $i--) {
        $cur = 0
        for ($j = 14; $j -ge 0; $j--) {
            $cur = $cur * 256 + $key[$j]
            $key[$j] = [math]::Floor($cur / 24)
            $cur = $cur % 24
        }
        $out  = $chars.Substring($cur, 1) + $out
        $last = $cur
    }
    if ($isWin8 -eq 1) { $out = $out.Substring(1).Insert($last, 'N') }
    return ($out -split '(.{5})' | Where-Object { $_ }) -join '-'
}
$dpid   = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DigitalProductId
$regKey = Get-KeyFromDigitalProductId $dpid

# Generic/default keys mean the device uses a digital license; the "key" itself is not useful
$genericKeys = @(
    'YTMG3-N6DYC-D3KB9-WR8CR-4CXCD', # Home
    'VK7JG-NPHTM-C97JM-9MPGT-3V66T', # Pro
    'W269N-WFGWX-YVC9B-4J6C9-T83GX', # Pro KMS client
    'NPPR9-FWDCX-D2C8J-H872K-2YT43'  # Enterprise KMS client
)
$isGeneric = $regKey -and ($genericKeys -contains $regKey)

# --- Edition check (firmware key edition vs installed edition) ---
$installedEdition = $os.Caption
$fwEdition = if ($fwKeyDesc -match 'Core|Home') { 'Home' } elseif ($fwKeyDesc -match 'Professional|Pro') { 'Pro' } else { $null }
$editionMismatch = $fwEdition -and ($installedEdition -notmatch $fwEdition)

# --- MDM device ID (from the agent's identity certificate, if present) ---
function Get-MdmDeviceId {
    $c = Get-ChildItem Cert:\LocalMachine\My |
         Where-Object { $_.Subject -match $IdentityPattern } |
         Sort-Object NotBefore -Descending | Select-Object -First 1
    if ($c -and $c.Subject -match $IdentityPattern) { return $Matches[1] }
    return $null
}
$deviceId = Get-MdmDeviceId

# --- Verdict ---
$atRisk = $true
$verdict = switch -Regex ($channel) {
    '^OEM' {
        if ($fwKey) {
            if ($editionMismatch) { "AT RISK - firmware key is $fwEdition but $installedEdition is installed. Reimage with $fwEdition or license the installed edition." }
            else { $atRisk = $false; 'SAFE - firmware key present; reimage with the same edition will auto-activate.' }
        } else { 'CHECK - OEM channel but no firmware key found.' }
    }
    '^RETAIL' {
        if ($isGeneric) { $atRisk = $false; 'DIGITAL LICENSE - reinstall the SAME edition on the same hardware; should reactivate online.' }
        else            { 'CAPTURE KEY - retail key exists only in this install. Save the Registry key below before reimaging.' }
    }
    '^VOLUME_MAK' { 'AT RISK - volume MAK key. May not reactivate after reimage; plan for proper licensing.' }
    '^VOLUME_KMS' { 'AT RISK - KMS client; only activates against a KMS server.' }
    default       { 'UNKNOWN - review manually.' }
}
if ($status -ne 'Licensed') { $verdict = "NOT ACTIVATED NOW ($status). " + $verdict; $atRisk = $true }

# --- Output ---
$report = @"
VERDICT:          $verdict
Manufacturer:     $($cs.Manufacturer)
Model:            $($cs.Model) ($($cs.SystemFamily))
Serial:           $($bios.SerialNumber)
BIOS:             $($bios.SMBIOSBIOSVersion)
Installed OS:     $installedEdition $($os.Version)
License status:   $status
License channel:  $channel
Active key (last 5): $($lic.PartialProductKey)
Firmware key:     $(if ($fwKey) { $fwKey } else { 'NONE' })
Firmware edition: $(if ($fwKeyDesc) { $fwKeyDesc } else { 'n/a' })
Registry key:     $(if ($regKey) { $regKey + $(if ($isGeneric) { ' (generic setup key - not a real license key)' } else { '' }) } else { 'n/a' })
MDM device ID:    $(if ($deviceId) { $deviceId } else { 'unknown' })
Leftovers:        $leftovers
Run at:           $(Get-Date -Format o)
"@

$report | Set-Content -Path $OutFile -Encoding UTF8
Write-Output $report

if ($WatchReenroll -and $deviceId) {
    # --- Watcher (runs every 15 minutes as SYSTEM) ---
    # 1. Re-enrolled into a new MDM record? Delete the output file so the audit re-runs.
    # 2. Output older than RefreshDays? Delete it so the result stays current.
    # 3. Output missing for 24 hours? The MDM no longer deploys the audit, so remove the
    #    watcher and its files.
    $watchDir  = Split-Path $OutFile
    $watchFile = Join-Path $watchDir 'Watch-Reenroll.ps1'
    $missFile  = Join-Path $watchDir 'missing-since.txt'
@"
`$out  = '$OutFile'
`$miss = '$missFile'
if (Test-Path `$out) {
    Remove-Item -LiteralPath `$miss -Force -ErrorAction SilentlyContinue
    `$saved = (Select-String -Path `$out -Pattern 'MDM device ID:\s+(\S+)' | Select-Object -First 1).Matches.Groups[1].Value
    `$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.Subject -match '$IdentityPattern' } | Sort-Object NotBefore -Descending | Select-Object -First 1
    `$now = `$null
    if (`$c -and `$c.Subject -match '$IdentityPattern') { `$now = `$Matches[1] }
    `$stale = ($RefreshDays -gt 0) -and ((Get-Item `$out).LastWriteTime -lt (Get-Date).AddDays(-$RefreshDays))
    if ((`$now -and `$saved -ne `$now) -or `$stale) { Remove-Item -LiteralPath `$out -Force -ErrorAction SilentlyContinue }
} else {
    if (-not (Test-Path `$miss)) { (Get-Date).ToString('o') | Set-Content -Path `$miss }
    elseif (((Get-Date) - [datetime](Get-Content `$miss | Select-Object -First 1)).TotalHours -ge 24) {
        Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath `$miss, '$watchFile' -Force -ErrorAction SilentlyContinue
    }
}
"@ | Set-Content -Path $watchFile -Encoding UTF8

    $action    = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
                 -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watchFile`""
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15) -RepetitionInterval (New-TimeSpan -Minutes 15)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

if ($FailOnRisk -and $atRisk) { exit 1 }
exit 0
