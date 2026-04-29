# Windows MDM Deployment Guide (Intune)

> Status: 2026-04-29. Templates pending; full implementation lands in v1.1. The macOS Jamf guide at `docs/deployment/mdm-jamf.md` is the working reference for the deployment shape.

This guide walks an IT admin through deploying BITSUMMIT Hardening as a managed Claude Code policy on a Windows fleet using Microsoft Intune. The end state mirrors the macOS goal: every enrolled Windows device has a vetted, ACL-protected `managed-settings.json` at `%PROGRAMDATA%\ClaudeCode\managed-settings.json` plus a sha256 manifest that flags any post-deployment tamper.

## Status disclosure

The artifacts referenced below are **templates** in this release. Their full PowerShell / MSI implementation is scheduled for v1.1. A Windows fleet operator can:

1. Compile a managed-settings.json from this repo today using `ccsec compile --target managed --os windows` (path tokens already resolve to Windows paths).
2. Deploy that JSON manually (see "Manual deployment" below) until the v1.1 artifacts ship.
3. Use the macOS Jamf guide as a contract for the v1.1 PowerShell installer surface.

## Prerequisites

- Microsoft Intune tenant with admin access; ability to upload Win32 apps and create Configuration Profiles.
- Windows fleet enrolled in Intune, running Windows 10 22H2 or Windows 11.
- Claude Code installed on the fleet (separate Intune app deployment, out of scope for this guide).
- A build / packaging host with:
  - Node 20.10 or later
  - pnpm 9.12 or later
  - This repository cloned (or the latest tagged release downloaded)

## Step 1: Compile the managed settings

On the build host:

```
git clone https://github.com/Bitsummit-Corp/claude-code-security.git
cd claude-code-security
pnpm install --frozen-lockfile
pnpm build

node packages/cli/bin/ccsec.js compile `
  --profile regulated `
  --target managed `
  --os windows `
  --settings-root packages/settings `
  --out C:\Temp\managed-settings.json
```

Inspect the result. Path tokens (`{HOME}`, `{TMP}`, etc.) resolve to Windows paths (`%USERPROFILE%`, `%TEMP%`, etc.) when `--os windows` is set.

## Step 2: Choose a deployment style

You have two viable options.

### Option A: PowerShell installer via Intune Win32 app

Pros: full programmatic control over file ACLs, hash manifest, and verification.
Cons: requires packaging the script + the JSON payload as a `.intunewin` Win32 app.

The PowerShell installer template (`installers/windows/install-managed.ps1`, **v1.1 deliverable**) does the equivalent of `install-managed.sh`:

```
# install-managed.ps1 (template; full implementation in v1.1)
param(
  [Parameter(Mandatory=$true)][ValidateSet('baseline','strict','regulated')]
  [string]$Profile
)

$Target = "$env:PROGRAMDATA\ClaudeCode\managed-settings.json"
$ManifestPath = "$env:PROGRAMDATA\ClaudeCode\.ccsec-manifest"

# Compile from the bundled rules
node packages\cli\bin\ccsec.js compile --profile $Profile --target managed --os windows --out $Target

# Lock down ACLs: SYSTEM and Administrators full control, Users read-only
$acl = Get-Acl $Target
$acl.SetAccessRuleProtection($true, $false)
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  'NT AUTHORITY\SYSTEM','FullControl','Allow')
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  'BUILTIN\Administrators','FullControl','Allow')
$usersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  'BUILTIN\Users','Read','Allow')
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($usersRule)
Set-Acl $Target $acl

# Mark read-only for additional safety
Set-ItemProperty $Target -Name IsReadOnly -Value $true

# Emit sha256 manifest
$hash = (Get-FileHash $Target -Algorithm SHA256).Hash.ToLower()
"$hash  $Target" | Out-File -FilePath $ManifestPath -Encoding ascii
```

Package as a `.intunewin` using the [Microsoft Win32 Content Prep Tool](https://learn.microsoft.com/en-us/mem/intune/apps/apps-win32-app-management) and upload to Intune as a Win32 app. Set:

- Install command: `powershell -ExecutionPolicy Bypass -File install-managed.ps1 -Profile regulated`
- Uninstall command: `powershell -ExecutionPolicy Bypass -File uninstall-managed.ps1`
- Detection rule: file exists at `%PROGRAMDATA%\ClaudeCode\managed-settings.json` with the expected sha256 (read from the manifest in step 3).

### Option B: ADMX-backed Configuration Profile

Pros: native Intune profile model, no script execution.
Cons: ADMX template required; a single `managed-settings.json` is not a natural fit for ADMX (which is registry-based). Reserved for a future plan if a registry-shape configuration model is added upstream.

For v0.8 / v1.0, **prefer Option A**.

## Step 3: Tamper detection (verify-managed.ps1)

The verification script template (`installers/windows/verify-managed.ps1`, **v1.1 deliverable**):

```
# verify-managed.ps1 (template; full implementation in v1.1)
$Target = "$env:PROGRAMDATA\ClaudeCode\managed-settings.json"
$ManifestPath = "$env:PROGRAMDATA\ClaudeCode\.ccsec-manifest"

if (-not (Test-Path $Target)) {
  Write-Error "managed-settings.json missing"; exit 2
}
if (-not (Test-Path $ManifestPath)) {
  Write-Error "manifest missing"; exit 2
}

$expected = (Get-Content $ManifestPath).Split(' ')[0]
$actual = (Get-FileHash $Target -Algorithm SHA256).Hash.ToLower()

if ($expected -ne $actual) {
  Write-Error "hash mismatch: expected $expected, got $actual"; exit 2
}

# Verify ACL still locked
$acl = Get-Acl $Target
$writable = $acl.Access | Where-Object {
  $_.IdentityReference -notin 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators' -and
  $_.FileSystemRights -match 'Write|Modify|FullControl'
}
if ($writable) {
  Write-Warning "ACL drift: non-admin write access detected"
}

Write-Host "managed-settings.json verified ($actual)"
```

Schedule via Intune's **Compliance Policies** as a custom PowerShell script that runs daily. Set the script's exit code 2 to mark the device non-compliant; this triggers Intune's standard alerting.

## Step 4: Manual deployment (interim, while v1.1 is in progress)

Until the PowerShell installer template ships:

1. Compile the JSON on the build host (Step 1).
2. Deploy via Intune as a "Custom" Win32 app whose install command is:
   ```
   powershell -Command "Copy-Item -Path .\managed-settings.json -Destination $env:PROGRAMDATA\ClaudeCode\ -Force; Set-ItemProperty $env:PROGRAMDATA\ClaudeCode\managed-settings.json -Name IsReadOnly -Value \$true"
   ```
3. Generate the sha256 manifest on the build host and ship it alongside the JSON.
4. Verify by running `Get-FileHash` manually or via a one-off Intune script.

This is operationally rougher than the v1.1 template but gives you protection today.

## Step 5: Periodic compliance check

Once the v1.1 templates ship:

- Schedule `verify-managed.ps1` daily via Intune Compliance.
- Tail the Windows Event Log channel `Application` for events written by the script.
- Treat any exit-code-2 result as a P2 alert and re-run the install policy.

## Reference: macOS contract

The macOS Jamf guide at `docs/deployment/mdm-jamf.md` is the working reference. The v1.1 Windows artifacts will mirror its surface:

- `install-managed.sh` (macOS) maps to `install-managed.ps1` (Windows).
- `verify-managed.sh` (macOS) maps to `verify-managed.ps1` (Windows).
- `chflags uchg` (macOS) maps to NTFS ACL + read-only attribute (Windows).
- sha256 manifest format (`<hash>  <path>`) is identical.
- Exit code 2 on mismatch is identical.

ADR-0006 documents why we chose Configuration Profile + companion script for macOS; the Windows analog is Win32 app + companion script for the same reasons (auditable, signed, no daemon).

## Roadmap

- v1.1: ship `install-managed.ps1`, `verify-managed.ps1`, `uninstall-managed.ps1`, and an `.intunewin` packaging script.
- v1.2: optional MSI distribution for environments that prefer MSI over Win32 app.
- v1.x: ADMX template once a registry-shape configuration model is upstreamed.

Issues and design feedback welcome at [github.com/Bitsummit-Corp/claude-code-security/issues](https://github.com/Bitsummit-Corp/claude-code-security/issues).
