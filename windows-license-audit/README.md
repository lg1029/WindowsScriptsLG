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

1. **Firmware key:** the OEM key in the device firmware, and which edition it is for
2. **Registry key:** the key Windows is currently using, decoded from `DigitalProductId`
3. **Active license:** activation status, license channel (OEM / Retail / Volume), last 5 characters of the active key
4. **Edition match:** firmware edition vs installed edition

Then it reports a **RESULT**:

| Result | Meaning | What to do |
|---|---|---|
| `SAFE TO REIMAGE` | Key is in firmware and the edition matches | Reimage with the same edition |
| `SAVE KEY FIRST` | Retail key that exists only in this install | Save the key shown, re-enter it after reimaging |
| `DIGITAL LICENSE` | Microsoft's activation servers hold the license | Reinstall the same edition; nothing to save |
| `AT RISK` | Edition mismatch or a volume (MAK/KMS) key | Fix the edition or plan proper licensing |
| `CHECK MANUALLY` | Unusual state | Review by hand |

## Sample output

```
RESULT:        SAFE TO REIMAGE
Why:           The product key is stored in the device firmware.
Action:        Reimage with the same Windows edition. It will activate on its own.
Key to save:   XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (also in firmware)

--- License details ---
Activation:    Activated
License type:  Manufacturer (OEM)
Firmware key:  XXXXX-XXXXX-XXXXX-XXXXX-XXXXX  ([4.0] Professional OEM:DM)
Installed key: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
```

Model, serial and BIOS aren't included because most MDMs already show them on the device record.

## Run locally

From an elevated PowerShell prompt:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsLicenseAudit.ps1
```

Optional parameters:

| Parameter | Purpose |
|---|---|
| `-OutFile <path>` | Change where the output copy is saved |
| `-FailOnRisk` | Exit `1` for anything other than `SAFE TO REIMAGE` / `DIGITAL LICENSE`, so at-risk devices show as failed in your tool |
| `-WatchReenroll` | Add a small scheduled task that re-triggers the audit when the device is re-enrolled into a new MDM record (see Option B) |
| `-RefreshDays <n>` | With `-WatchReenroll`: re-run the audit when the result is older than *n* days. Default `7`, `0` turns it off |
| `-Cleanup` | Remove leftovers from an earlier app-style deployment before running. Use when switching to a script item |
| `-IdentityPattern <regex>` | How to find the MDM's device ID in the machine certificate store. Default: `CN=Agent Identity (<GUID>)` |

## Deploy remotely with an MDM

### Option A: App/package item (recommended)

Works on new and already-enrolled devices, and keeps the result visible after a re-enrollment.

1. Zip `Get-WindowsLicenseAudit.ps1` on its own.
2. **Install command.** Use the **full path** to PowerShell. Some agents don't resolve `powershell.exe` on their own and fail with no exit code.
   ```
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-WindowsLicenseAudit.ps1 -WatchReenroll
   ```
3. **Uninstall command:**
   ```
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "Remove-Item 'C:\ProgramData\LicenseAudit' -Recurse -Force; Unregister-ScheduledTask -TaskName 'LicenseAudit-ReenrollWatch' -Confirm:$false"
   ```
4. **Detection rule:** file exists at `C:\ProgramData\LicenseAudit\LicenseAudit.txt`
5. **Install behavior:** install and continuously enforce.

Many MDMs show the install command's standard output in the device's install log, which is where you'll read the verdict.

#### How it stays current

| Situation | What happens |
|---|---|
| New device enrolls | Output file missing, so the audit runs |
| Device already enrolled | Output file missing, so the audit runs |
| Wiped and re-enrolled | Wipe removed the file, so the audit runs |
| Record deleted and re-enrolled without a wipe | Within 15 minutes the watcher sees a new MDM device ID and deletes the old output file; the audit runs at the next agent check (about 30 minutes total) |

The watcher only works if your MDM agent puts a device-identity certificate in `Cert:\LocalMachine\My` whose subject contains the device ID. Check the output's `MDM device ID` line: if it says `unknown`, set `-IdentityPattern` to match your agent's certificate, or leave `-WatchReenroll` off.

To re-run the audit by hand on a device, delete `C:\ProgramData\LicenseAudit\LicenseAudit.txt`.

#### Cleanup when you stop deploying it

Some MDMs don't run the uninstall command when you unassign an app. The watcher handles this itself: if the output file stays missing for 24 hours (nothing re-ran the audit), it removes its scheduled task and helper files. The output file from the last run remains until it's refreshed or deleted.

Every run also reports a `Leftovers:` line listing anything an earlier deployment left behind.

### Option B: Script item

1. Create a Windows PowerShell script item and paste in the script. Don't pass `-WatchReenroll`. If you're switching from Option A, pass `-Cleanup` once to remove its leftovers.
2. Run it in **64-bit** PowerShell, as **SYSTEM**.
3. Leave the remediation script empty. There is nothing to fix automatically.
4. Optionally pass `-FailOnRisk` so risky devices are flagged.
5. Read the verdict from the script's standard output in your console.

Some MDMs only run script items when a device enrolls, so already-enrolled devices may never pick one up. If that happens, use Option A.

## Check a device manually

```powershell
slmgr /dli    # license channel and partial key
(Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey   # firmware key, if any
```

## Notes and limitations

- **Can't write keys to firmware.** The OEM key is written at the factory and the area is write-protected. Store captured keys somewhere safe instead (MDM device notes, password manager), keyed by serial number.
- **Re-activating after a reimage.** For `SAVE KEY FIRST` devices, a follow-up script can run `slmgr /ipk <key>` and `slmgr /ato`. Treat any script that contains keys as sensitive.
- **Volume/reseller keys.** If many devices come back `AT RISK` on a volume channel, the long-term fix is proper licensing (for example a MAK key from Microsoft volume licensing, deployable to all devices with one script).
- **Key visibility.** Full product keys appear in the script output. Anyone with access to your management console's logs can see them.
- **Digital licenses** show a generic key in the registry. That's expected and not a real key to save.

## Requirements

- Windows 10 / 11
- Windows PowerShell 5.1
- Run as Administrator or SYSTEM
