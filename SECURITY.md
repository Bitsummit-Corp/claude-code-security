# Security Policy

## Reporting a Vulnerability

Two channels, in this order of preference:

1. **GitHub Security Advisories** (preferred): file a private advisory at <https://github.com/Bitsummit-Corp/claude-code-governance/security/advisories>. This routes directly into our triage queue and creates the GHSA record we publish on disclosure.
2. **Email** `security@bitsummit.com`. PGP key fingerprint is **pending** (generation tracked in `docs/release-engineering.md`); plain email is acceptable in the interim, but treat the contents as untrusted by transport.

Please do not file public GitHub issues for vulnerabilities.

## Disclosure Timeline

| Phase | SLA | Notes |
|---|---|---|
| Acknowledgement | 72 hours | We reply within 72h to confirm receipt and assign a triage owner. |
| Triage to fix-or-roadmap (HIGH severity) | 14 days | "Fix-or-roadmap" means a patch lands or a written remediation plan with a target date is shared with the reporter. |
| Triage to fix-or-roadmap (MEDIUM severity) | 30 days | Same definition. LOW severity follows MEDIUM unless the reporter prefers a longer window. |
| Default disclosure window | 90 days | From acknowledgement to public GHSA publish. Extensions are negotiable; coordinated disclosure is the default. |

CRITICAL severity (active exploitation in the wild, no available mitigation) collapses the timeline to whatever the reporter and maintainers agree is fastest. We will not delay a public advisory past the point where users cannot defend themselves.

## Scope

In scope: anything in `packages/`, `installers/`, default profiles (`packages/settings/profiles/`), and shipped binaries (`ccsec-{macos-arm64,macos-x64,linux-x64,windows-x64}`).

Out of scope: third-party hooks added by users, downstream Claude Code itself, OS-level security primitives (the OS kernel, the user's keychain, the user's shell).

## Hall of Thanks

Reporters are listed here on disclosure with their permission. The list is currently empty; the first verified reporter will be added when GHSA-0001 publishes.

## PGP Key

PGP key fingerprint is **pending** as of 2026-04-29. Generation procedure and publication path are in `docs/release-engineering.md` ("PGP key generation"). Until the key is published, prefer the GitHub Security Advisory channel.

## Security Carve-Out in SemVer

Fixes that *tighten* policy (close a bypass) ship in PATCH versions and are flagged in `CHANGELOG.md` under `### Security`. This is an intentional carve-out from strict SemVer: a tightening fix may break a workflow that depended on the bypass, but we treat that as a bug being repaired rather than a breaking change.
