# MDM Deployment via Jamf (macOS)

This guide walks an IT admin through deploying BITSUMMIT Hardening as a managed Claude Code policy on a fleet of Macs using Jamf Pro.

The end state: every Mac in the targeted smart group has a vetted, root-owned, immutable `managed-settings.json` at `/Library/Application Support/ClaudeCode/managed-settings.json`, plus a sha256 manifest that flags any post-deployment tamper.

## Prerequisites

- Jamf Pro instance with admin access and the ability to upload Configuration Profiles.
- Mac fleet enrolled in Jamf and running macOS 14 or later.
- Claude Code installed on the fleet (separate Jamf policy, out of scope for this guide).
- A build / packaging host with:
  - Node 20.10 or later
  - pnpm 9.12 or later
  - This repository cloned (or the latest tagged release downloaded)

## Step 1: Compile the managed settings

On the build host:

```
git clone https://github.com/Bitsummit-Corp/claude-code-governance.git
cd claude-code-security
pnpm install --frozen-lockfile
pnpm build
```

Pick a profile that matches your fleet's risk posture. See `README.md` for the full chooser; common picks:

- `regulated` for healthcare, legal, or public-sector fleets
- `strict` for general team / shared-infra fleets
- `baseline` for low-friction, warning-only deployments

Compile:

```
node packages/cli/bin/ccsec.js compile \
  --profile regulated \
  --target managed \
  --os macos \
  --settings-root packages/settings \
  --out /tmp/managed-settings.json
```

Inspect the result. The `target managed` flag tells the compiler to emit a settings file shaped for `/Library/Application Support/ClaudeCode/managed-settings.json` rather than the per-user `~/.claude/settings.json`.

```
jq . /tmp/managed-settings.json | head
```

## Step 2: Choose a deployment style

You have two viable options. Pick one.

### Option A: Embed the payload in the Configuration Profile (self-contained)

Pros: one artifact to upload. No git access required on enrolled Macs.
Cons: redeploying = re-uploading the profile.

```
base64 -i /tmp/managed-settings.json | tr -d '\n' > /tmp/managed-settings.b64
```

Open `installers/macos/jamf/com.bitsummit.claude-code-security.mobileconfig.xml`. Replace the `<!-- generated -->` placeholder inside `<key>managed_settings_base64</key>` with the contents of `/tmp/managed-settings.b64`. Update `<key>profile</key>` if you compiled a non-`regulated` profile.

### Option B: Profile + companion policy that runs install-managed.sh

Pros: smaller profile. Easier to redeploy by re-running the policy.
Cons: requires the repository to be reachable from enrolled Macs (e.g. via Jamf File Share, an internal mirror, or a curl-installable tarball).

In this style, the `.mobileconfig` is informational and the actual write is done by a Jamf policy that runs:

```
sudo /path/to/installers/macos/install-managed.sh --profile regulated
```

Choose Option A unless your fleet has reliable network access to the build artifact. For most regulated environments, Option A is preferable because it is self-contained and signed alongside the profile.

## Step 3: Create the Jamf Configuration Profile

1. Sign in to Jamf Pro. Go to **Computers** -> **Configuration Profiles**.
2. Click **Upload**. Select the edited `com.bitsummit.claude-code-security.mobileconfig.xml`.
3. Set the profile name to `BITSUMMIT Hardening - Claude Code Managed Settings`.
4. Set **Distribution Method** to `Install Automatically`.
5. Set **Level** to `Computer Level`.
6. On the **Options** tab, confirm the Custom Settings payload preview shows your intended payload.

## Step 4: Scope to a smart group

1. Create a smart group at **Computers** -> **Smart Computer Groups** -> **New**.
2. Name it `Claude Code - Managed`.
3. Criteria: `Application Title` `is` `Claude Code` (adjust for your fleet's bundle ID).
4. Save.
5. Back on the configuration profile, go to the **Scope** tab and add the smart group as a target. Save.

## Step 5: Verify on a test machine

Limit scope to one test Mac first. Wait for the profile to install (force a Jamf check-in if needed: `sudo jamf policy`).

Then on the test Mac:

```
sudo ./installers/macos/verify-managed.sh
```

Expected output: a single `OK` line.

If you instead see:

| Output | Meaning | Action |
|---|---|---|
| `ERROR: ... missing` | Profile didn't write the file. | Check Jamf logs. Re-scope. |
| `ERROR: tamper detected` | sha256 mismatch. | Investigate. Reinstall. |
| `WARN: ... not flagged uchg` | File is mutable. | Reinstall via `install-managed.sh` to restore the immutable flag. |

Once the test Mac reports `OK`, broaden the scope to the full smart group.

## Step 6: Schedule periodic verification

Periodic verification turns tamper detection from "an admin runs it" into "the fleet reports drift automatically".

Option 1: Jamf Extension Attribute. Create an Extension Attribute that runs:

```
#!/bin/bash
result=$(/path/to/installers/macos/verify-managed.sh 2>&1)
echo "<result>$result</result>"
```

Sample on a daily inventory cycle. Build a smart group that filters for `Extension Attribute - Claude Code Verify` `does not contain` `OK`. That smart group is your tamper alert.

Option 2: cron / launchd. Drop a LaunchDaemon at `/Library/LaunchDaemons/com.bitsummit.ccsec-verify.plist` that runs `verify-managed.sh` every 6 hours and logs to syslog. Then forward syslog to your SIEM.

Option 1 is preferred if you already operate Jamf compliance reporting. Option 2 is preferred if you have a centralized log pipeline.

## Tamper response

When `verify-managed.sh` reports non-zero on a fleet machine, treat it as a security incident:

1. **Contain.** Pull the offending Mac out of the trusted scope. Block its access to internal resources via your network access control system.
2. **Investigate.** SSH or Apple Remote Desktop in. Diff the current `managed-settings.json` against the expected payload. Check the audit log at `/Library/Application Support/ClaudeCode/audit.log` for evidence of how the file was modified.
3. **Restore.** Re-run `install-managed.sh --profile <profile>` (or re-push the Jamf profile) to rewrite the file with the immutable flag.
4. **Report.** File a ticket in your security tracker. If the modification looks intentional rather than a corrupt deploy, escalate to incident response.

## FAQ

**Why immutable (`uchg`)?** Without it, a user with sudo can edit the managed settings and disable hooks at will. The `uchg` flag means even root cannot edit the file without first running `chflags nouchg`, which itself shows up in the audit trail.

**Will `chflags uchg` survive macOS upgrades?** Yes. The flag is stored in the file's HFS+/APFS metadata and is preserved across upgrades. Reinstalling Claude Code does not clear it.

**Can a user circumvent it by modifying `~/.claude/settings.json`?** The settings precedence checker hook flags any `~/.claude/settings.json` that contradicts the managed file. The MDM-bypass detector flags attempts to disable hooks. Both are part of the strict and regulated profiles.

**What if I need to roll back?** Run `sudo chflags nouchg /Library/Application\ Support/ClaudeCode/managed-settings.json` then redeploy. Or push an empty Jamf profile that removes the payload.
