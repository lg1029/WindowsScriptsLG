# Windows License Audit

A read-only PowerShell script that tells you **how a Windows device is licensed** and **whether reimaging it will lose activation**, and captures the product key where one can be captured.

Run it locally or deploy it remotely through your MDM/RMM, then read the verdict from the script output.

## Why

Some devices reactivate on their own after a clean reinstall and some don't. It depends on where the license comes from:

| License source | What happens on reimage |
|---|---|
| **Firmware (OEM) key** embedded by the manufacturer | Clean install reads it and auto-activates (if the same edition is installed) |
| **Retail key** typed in after purchase | Lives only in the installed OS, so it's lost on wipe unless captured first |
| **Digital license** tied to the hardware | Usually reactivates if the same edition is reinstalled on unchanged hardware |
| **Volume key (MAK/KMS)**, often reseller-supplied | Frequently can't be reused, so a capture alone won't help |
| **Edition mismatch** (e.g. firmware key is Home, Pro installed) | Won't activate until the matching edition or a valid key is used |

Devices that shipped without an OS, or were bought through resellers, often have **no firmware key**. Scripts that only read the firmware key come back empty on those.

## What the script checks

1. **Hardware:** manufacturer, model, serial, BIOS version
2. **Firmware key:** the OEM key in the device firmware, and which edition it is for
3. **Registry key:** the key Windows is currently using, decoded from `DigitalProductId`
4. **Active license:** activation status, license channel (OEM / Retail / Volume), last 5 characters of the active key
5. **Edition match:** firmware edition vs installed edition

Then it prints a **VERDICT**:

| Verdict | Meaning | Action |
|---|---|---|
| `SAFE` | Firmware key present, edition matches | Reimage with the same edition |
| `CAPTURE KEY` | Retail key, not in firmware | Save the registry key before reimaging, re-enter after |
| `DIGITAL LICENSE` | Generic key shown; license held by Microsoft activation servers | Reinstall the same edition; no key to save |
| `AT RISK` | Edition mismatch or volume (MAK/KMS) key | Fix edition, or plan proper licensing |
| `CHECK` / `UNKNOWN` | Unusual state | Review manually |

It changes nothing on the device. The only file it writes is a copy of its output (default `C:\ProgramData\LicenseAudit\LicenseAudit.txt`).

## Sample output

```
VERDICT:          SAFE - firmware key present; reimage with the same edition will auto-activate.
Manufacturer:     <manufacturer>
Model:            <model> (<family>)
Serial:           <serial>
BIOS:             <bios version>
Installed OS:     Microsoft Windows 11 Pro 10.0.26200
License status:   Licensed
License channel:  OEM_DM
Active key (last 5): XXXXX
Firmware key:     XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
Firmware edition: [4.0] Professional OEM:DM
Registry key:     XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
Run at:           2026-01-01T12:00:00.0000000-05:00
```

## Run locally

From an elevated PowerShell prompt:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsLicenseAudit.ps1
```

Optional parameters:

| Parameter | Purpose |
|---|---|
| `-OutFile <path>` | Change where the output copy is saved |
| `-FailOnRisk` | Exit `1` for anything other than `SAFE` / `DIGITAL LICENSE`, so at-risk devices show as failed in your tool |

## Deploy remotely with an MDM

### Option A: Script item (preferred if your MDM supports it)

1. Create a Windows PowerShell script item and paste in the script.
2. Run it in **64-bit** PowerShell, as **SYSTEM**.
3. Leave the remediation script empty. There is nothing to fix automatically.
4. Optionally pass `-FailOnRisk` so risky devices are flagged.
5. Read the verdict from the script's standard output in your console.

### Option B: App/package item that runs a script

If your MDM can't run scripts directly but can deploy a zipped package with a custom install command:

1. Zip `Get-WindowsLicenseAudit.ps1` on its own.
2. **Install command.** Use the **full path** to PowerShell. Some agents don't resolve `powershell.exe` on their own and fail with no exit code.
   ```
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsLicenseAudit.ps1
   ```
3. **Uninstall command:**
   ```
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "Remove-Item 'C:\ProgramData\LicenseAudit\LicenseAudit.txt' -Force"
   ```
4. **Detection rule:** file exists at `C:\ProgramData\LicenseAudit\LicenseAudit.txt`
5. **Install behavior:** install once per device.
6. To re-run later, bump the package version.

Many MDMs show the install command's standard output in the device's install log, which is where you'll read the verdict.

## Check a device manually

```powershell
slmgr /dli    # license channel and partial key
(Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey   # firmware key, if any
```

## Notes and limitations

- **Can't write keys to firmware.** The OEM key is written at the factory and the area is write-protected. Store captured keys somewhere safe instead (MDM device notes, password manager), keyed by serial number.
- **Re-activating after a reimage.** For `CAPTURE KEY` devices, a follow-up script can run `slmgr /ipk <key>` and `slmgr /ato`. Treat any script that contains keys as sensitive.
- **Volume/reseller keys.** If many devices come back `AT RISK` on a volume channel, the long-term fix is proper licensing (for example a MAK key from Microsoft volume licensing, deployable to all devices with one script).
- **Key visibility.** Full product keys appear in the script output. Anyone with access to your management console's logs can see them.
- **Digital licenses** show a generic key in the registry. That's expected and not a real key to save.

## Requirements

- Windows 10 / 11
- Windows PowerShell 5.1
- Run as Administrator or SYSTEM
