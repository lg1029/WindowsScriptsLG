<#
.SYNOPSIS
    Audits how a Windows device is licensed and whether a reimage will lose activation.

.DESCRIPTION
    Read-only. Collects hardware details, the firmware (OEM) product key, the installed
    product key decoded from the registry, the active license channel, and the edition,
    then prints a VERDICT line describing reimage risk.

    The only thing written to disk is a copy of the output (see -OutFile).

.PARAMETER OutFile
    Where to save a copy of the output. Default: C:\ProgramData\LicenseAudit\LicenseAudit.txt
    Useful as a detection file when deploying through an MDM "app" item.

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
    [switch]$FailOnRisk
)

$ErrorActionPreference = 'SilentlyContinue'

# Relaunch in 64-bit PowerShell if started from a 32-bit process on 64-bit Windows
if ($env:PROCESSOR_ARCHITEW6432 -and -not [Environment]::Is64BitProcess) {
    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-OutFile', $OutFile)
    if ($FailOnRisk) { $argsList += '-FailOnRisk' }
    & "$env:WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" @argsList
    exit $LASTEXITCODE
}

New-Item -ItemType Directory -Path (Split-Path $OutFile) -Force | Out-Null

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
Run at:           $(Get-Date -Format o)
"@

$report | Set-Content -Path $OutFile -Encoding UTF8
Write-Output $report

if ($FailOnRisk -and $atRisk) { exit 1 }
exit 0
