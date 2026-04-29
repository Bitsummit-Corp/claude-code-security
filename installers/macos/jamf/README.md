# Jamf Deployment - BITSUMMIT Hardening

This directory contains the Jamf admin tooling for deploying BITSUMMIT Hardening as a managed Claude Code policy.

## Files

| File | Purpose |
|---|---|
| `com.bitsummit.claude-code-security.mobileconfig.xml` | Jamf Configuration Profile template (Custom Settings payload). Carries the compiled `managed-settings.json` as a base64 string. |
| `README.md` | This file. |

For the per-host installer that the profile invokes, see `../install-managed.sh`. For verification, see `../verify-managed.sh`. For the full IT-admin workflow, see `docs/deployment/mdm-jamf.md`.

## Quick Start

### 1. Compile the managed settings on your build host

```
ccsec compile \
  --profile regulated \
  --target managed \
  --os macos \
  --out /tmp/managed-settings.json
```

Use `regulated` for healthcare / legal / public sector fleets. Use `strict` for general team / shared-infra fleets. Use `baseline` for low-friction warning-only deployments.

### 2. Base64-embed the payload into the .mobileconfig

```
base64 -i /tmp/managed-settings.json | tr -d '\n' > /tmp/managed-settings.b64
```

Open `com.bitsummit.claude-code-security.mobileconfig.xml`. Replace the `<!-- generated -->` placeholder inside the `<key>managed_settings_base64</key>` value with the contents of `/tmp/managed-settings.b64`. Update the `<key>profile</key>` value to match the profile you compiled.

> **Tip.** Many sites prefer to keep the payload thin and instead pair this profile with a Jamf policy that pulls `install-managed.sh` from a managed git checkout and runs it as root. Both approaches are valid; choose based on whether your fleet has reliable `git` + Node 20 access.

### 3. Import into Jamf Pro

1. Sign in to Jamf Pro -> **Computers** -> **Configuration Profiles** -> **Upload**.
2. Select the edited `com.bitsummit.claude-code-security.mobileconfig.xml`.
3. Confirm the payload preview shows your intended profile name (e.g. `regulated`).

### 4. Scope to a smart group

Create a smart group that filters to dev machines (e.g. criteria: "Application Title is Claude Code" or membership in your dev-fleet smart group).

Scope the profile to that smart group on the **Scope** tab.

### 5. Deploy to a test machine first

Limit scope to one test Mac. Confirm:

```
sudo ./installers/macos/verify-managed.sh
# expected: OK
```

If the script reports tamper detected, roll back the profile from Jamf, investigate, redeploy.

## Verification

Run the verifier on any managed Mac:

```
sudo ./installers/macos/verify-managed.sh
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Managed settings file matches manifest hash. `uchg` flag present. OK. |
| 1 | Managed settings file or manifest is missing. Reinstall. |
| 2 | Hash mismatch (tamper detected). Reinstall and investigate. |

A non-zero exit on a fleet machine is the signal to escalate to your security team.

## Notes for testing locally without Jamf

The `install-managed.sh` and `verify-managed.sh` scripts are sudo-only because they write to `/Library/Application Support/ClaudeCode/`. The bats test suite runs as a non-elevated user and intentionally does not exercise these scripts; the per-user `install.sh` + `verify.sh` cover the unit-test territory.

To smoke-test the managed scripts on your local admin workstation:

```
sudo ./installers/macos/install-managed.sh --profile regulated
sudo ./installers/macos/verify-managed.sh
sudo chflags nouchg "/Library/Application Support/ClaudeCode/managed-settings.json"
sudo rm -rf "/Library/Application Support/ClaudeCode"
```

The final two commands are the cleanup hatch (remove the immutable flag, then delete).
