# Linux MDM Deployment Guide

> Status: 2026-04-29. Templates pending; full implementation lands in v1.2. The macOS Jamf guide at `docs/deployment/mdm-jamf.md` is the working reference for the deployment shape.

This guide walks an IT admin through deploying BITSUMMIT Hardening as a managed Claude Code policy on a Linux fleet. The end state mirrors the macOS goal: every managed device has a vetted, root-owned `managed-settings.json` at `/etc/claude-code/managed-settings.json` (or `/etc/ClaudeCode/managed-settings.json` for parity with the macOS path) plus a sha256 manifest that flags any post-deployment tamper.

Linux fleets vary widely. This guide covers the three most common shapes:

- **Ansible-managed dev workstations** (e.g., engineering laptops on Ubuntu / Fedora).
- **Image-baked containers / VMs** (e.g., dev-container images, GitHub Codespaces images, internal cloud-dev VMs).
- **Distro packages** (`.deb` / `.rpm`) for environments with a centralized package repo.

## Status disclosure

The artifacts referenced below are **templates** in this release. Their full implementation is scheduled for v1.2. A Linux fleet operator can:

1. Compile a managed-settings.json from this repo today using `ccsec compile --target managed --os linux`.
2. Deploy that JSON manually (see "Manual deployment" below) until the v1.2 artifacts ship.
3. Use the macOS Jamf guide as a contract for the v1.2 installer surface.

## Prerequisites

- A Linux fleet running a glibc-based distribution (Ubuntu 22.04+, Debian 12+, Fedora 39+, RHEL 9+) or a musl-based distribution (Alpine 3.18+).
- Claude Code installed on the fleet (separate process, out of scope for this guide).
- A build / packaging host with:
  - Node 20.10 or later
  - pnpm 9.12 or later
  - This repository cloned (or the latest tagged release downloaded)
- Root access on target machines (via Ansible become, sudo, or image-baked).

## Step 1: Compile the managed settings

On the build host:

```
git clone https://github.com/Bitsummit-Corp/claude-code-governance.git
cd claude-code-security
pnpm install --frozen-lockfile
pnpm build

node packages/cli/bin/ccsec.js compile \
  --profile regulated \
  --target managed \
  --os linux \
  --settings-root packages/settings \
  --out /tmp/managed-settings.json
```

Inspect the result. Path tokens (`{HOME}`, `{TMP}`, etc.) resolve to Linux paths when `--os linux` is set.

## Step 2: Choose a deployment style

You have three viable options. Pick the one that matches your fleet's existing discipline.

### Option A: Shell installer template (`install-managed.sh`)

Pros: simplest. One file, one command. Good for image-baked deployments and one-off rollouts.
Cons: requires you to wire it into your config-management tool (Ansible, Salt, Puppet, etc.).

The shell installer template (`installers/linux/install-managed.sh`, **v1.2 deliverable**) does the equivalent of the macOS script:

```
#!/usr/bin/env bash
# install-managed.sh (template; full implementation in v1.2)
set -euo pipefail

PROFILE="${1:-regulated}"
TARGET="/etc/ClaudeCode/managed-settings.json"
MANIFEST="/etc/ClaudeCode/.ccsec-manifest"

if [ "$EUID" -ne 0 ]; then
  echo "must run as root" >&2
  exit 1
fi

mkdir -p "$(dirname "$TARGET")"

# Compile from the bundled rules
node packages/cli/bin/ccsec.js compile \
  --profile "$PROFILE" \
  --target managed \
  --os linux \
  --out "$TARGET"

# Lock down: root-owned, mode 0644
chown root:root "$TARGET"
chmod 0644 "$TARGET"

# Set immutable flag where supported (ext4, btrfs, xfs)
if command -v chattr >/dev/null 2>&1; then
  chattr +i "$TARGET" 2>/dev/null || \
    echo "chattr +i unsupported on this fs; rely on root ownership" >&2
fi

# Emit sha256 manifest
HASH=$(sha256sum "$TARGET" | awk '{print $1}')
printf '%s  %s\n' "$HASH" "$TARGET" > "$MANIFEST"
chmod 0644 "$MANIFEST"

echo "managed-settings.json installed at $TARGET (sha256 $HASH)"
```

### Option B: Ansible role (`bitsummit.ccsec`)

Pros: idempotent. Plays well with existing Ansible-managed fleets. Easy to roll back via the playbook.
Cons: requires Ansible.

The Ansible role template (`installers/linux/ansible/`, **v1.2 deliverable**) wraps Option A in standard Ansible task structure:

```
# tasks/main.yml (template; full implementation in v1.2)
- name: Ensure managed-settings.json
  copy:
    src: managed-settings.json
    dest: /etc/ClaudeCode/managed-settings.json
    owner: root
    group: root
    mode: '0644'
  register: managed_settings

- name: Set immutable flag
  command: chattr +i /etc/ClaudeCode/managed-settings.json
  when: managed_settings.changed

- name: Emit sha256 manifest
  shell: sha256sum /etc/ClaudeCode/managed-settings.json > /etc/ClaudeCode/.ccsec-manifest
  when: managed_settings.changed
```

### Option C: `.deb` / `.rpm` package

Pros: distributable via internal package repo; easy mass-deploy.
Cons: requires you to maintain the package's release cadence alongside ccsec releases.

The packaging templates (`installers/linux/deb/`, `installers/linux/rpm/`, **v1.2 deliverable**) build a binary package whose pre-install hook compiles the JSON and whose post-install hook applies the ACLs and emits the manifest.

For internal package repos (Artifactory, Nexus, custom apt repo), pair this with a daily `apt-get update && apt-get upgrade ccsec-managed-settings` cron to pick up new releases.

## Step 3: Tamper detection (verify-managed.sh)

The verification script template (`installers/linux/verify-managed.sh`, **v1.2 deliverable**) mirrors the macOS verifier:

```
#!/usr/bin/env bash
# verify-managed.sh (template; full implementation in v1.2)
set -euo pipefail

TARGET="/etc/ClaudeCode/managed-settings.json"
MANIFEST="/etc/ClaudeCode/.ccsec-manifest"

if [ ! -f "$TARGET" ]; then
  echo "managed-settings.json missing" >&2
  exit 2
fi
if [ ! -f "$MANIFEST" ]; then
  echo "manifest missing" >&2
  exit 2
fi

EXPECTED=$(awk '{print $1}' "$MANIFEST")
ACTUAL=$(sha256sum "$TARGET" | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "hash mismatch: expected $EXPECTED, got $ACTUAL" >&2
  exit 2
fi

# Verify immutable flag still set (best-effort)
if command -v lsattr >/dev/null 2>&1; then
  if ! lsattr "$TARGET" 2>/dev/null | head -c 5 | grep -q i; then
    echo "warning: immutable flag missing on $TARGET" >&2
  fi
fi

# Verify root ownership
if [ "$(stat -c '%u:%g' "$TARGET")" != "0:0" ]; then
  echo "warning: $TARGET is not root-owned" >&2
fi

echo "managed-settings.json verified ($ACTUAL)"
```

Schedule via systemd timer:

```
# /etc/systemd/system/ccsec-verify.service
[Unit]
Description=ccsec managed-settings tamper check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/verify-managed.sh

# /etc/systemd/system/ccsec-verify.timer
[Unit]
Description=Run ccsec verify daily
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
```

Or via cron:

```
0 3 * * * /usr/local/bin/verify-managed.sh >> /var/log/ccsec-verify.log 2>&1
```

Pipe the log to your fleet's central log aggregator (rsyslog, journald-remote, vector). Treat any exit-code-2 line as a P2 alert.

## Step 4: Manual deployment (interim, while v1.2 is in progress)

Until the templates ship:

1. Compile the JSON on the build host (Step 1).
2. `scp` to each target, place at `/etc/ClaudeCode/managed-settings.json`.
3. `chown root:root` + `chmod 0644` + `chattr +i`.
4. Generate sha256 manifest manually: `sha256sum /etc/ClaudeCode/managed-settings.json > /etc/ClaudeCode/.ccsec-manifest`.
5. Verify by running `sha256sum -c <(awk '{print $1"  "$2}' /etc/ClaudeCode/.ccsec-manifest)`.

For Ansible-managed fleets, wrap the above in an ad-hoc playbook today; replace with the proper role in v1.2.

## Reference: macOS contract

The macOS Jamf guide at `docs/deployment/mdm-jamf.md` is the working reference. The v1.2 Linux artifacts will mirror its surface:

- `install-managed.sh` (macOS) maps to `install-managed.sh` (Linux); the surface is nearly identical.
- `verify-managed.sh` (macOS) maps to `verify-managed.sh` (Linux); same exit codes, same manifest format.
- `chflags uchg` (macOS) maps to `chattr +i` (Linux ext4 / btrfs / xfs).
- sha256 manifest format (`<hash>  <path>`) is identical.
- Exit code 2 on mismatch is identical.

ADR-0006 documents why we chose per-OS path templates over auto-detection. The Linux setup uses the same approach: `--os linux` produces Linux-shaped paths.

## SELinux / AppArmor note

On RHEL / Fedora with SELinux enforcing, the managed-settings file inherits the parent dir's context. If your fleet uses a custom SELinux policy module for Claude Code, ensure the file's context allows the Claude Code process to read it. The template installer does NOT modify SELinux contexts; the operator is responsible for the local policy.

On Ubuntu / Debian with AppArmor, the same principle applies: the Claude Code AppArmor profile (if you ship one) must include `/etc/ClaudeCode/managed-settings.json r,`.

## Roadmap

- v1.2: ship `install-managed.sh`, `verify-managed.sh`, the Ansible role, and `.deb` / `.rpm` packaging.
- v1.x: SELinux policy module; AppArmor profile snippet; systemd unit for read-only bind-mount of `/etc/ClaudeCode`.

Issues and design feedback welcome at [github.com/Bitsummit-Corp/claude-code-governance/issues](https://github.com/Bitsummit-Corp/claude-code-governance/issues).
