# Release Engineering Runbook

> Canonical procedure for cutting, signing, and publishing a `claude-code-security` release. Owner: maintainer. Audience: maintainer + future co-maintainers.

This runbook covers the seven stages of a release: pre-release gates, version + tag, CI release pipeline, signing slots (maintainer-action), post-release verification, the security advisory pipeline, and backports across the `release/v1.x` line.

---

## 1. Pre-Release Gates

Run these locally before tagging. CI runs them again, but a local failure is cheaper.

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm test
pnpm gen:docs       # regenerate hook docs + coverage matrix; commit any drift
```

Verify CHANGELOG:

- An entry exists for the new version with today's date (`date '+%Y-%m-%d'`).
- The `[Unreleased]` block is moved to the new version block.
- Sections follow Keep a Changelog order: Added, Changed, Deprecated, Removed, Fixed, Security.

Verify version bumps in every published package:

```bash
for pkg in core hooks settings cli rules plugin meta; do
  echo "--- $pkg ---"
  jq -r '.version' "packages/$pkg/package.json"
done
```

Versions across `packages/*` should match the tag being cut (the meta package's version is the canonical user-facing version).

## 2. Version + Tag

```bash
# Edit each packages/*/package.json to the new version; commit.
git add packages/*/package.json CHANGELOG.md
git commit -m "release: vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

The tag push triggers `.github/workflows/release.yml`.

## 3. CI Release Pipeline

`release.yml` runs three jobs in series:

| Job | Runner | Output |
|---|---|---|
| `publish` | `macos-14` | npm publish (per-package, `--provenance`); SBOM (`sbom.cyclonedx.json`) attached to the GitHub release. |
| `sea-build` | matrix (`macos-14`, `macos-13`, `ubuntu-latest`, `windows-latest`) | `ccsec-{target}` Node SEA binaries uploaded as workflow artifacts. |
| `release-manifest` | `ubuntu-latest` | Downloads SEA artifacts, emits `SHA256SUMS`, attaches binaries + manifest to the GitHub release. |

Provenance: `npm publish --provenance` produces a SLSA Level 3 attestation when run from GitHub Actions with `id-token: write` (already wired). The attestation is automatically published with the npm package and viewable on the package page.

## 4. Signing Slots (Maintainer-Action)

The pipeline produces unsigned binaries by default. To enable signed releases, the maintainer must provision keys and add the corresponding signing steps. Until then, `SHA256SUMS` is the integrity reference.

### 4a. PGP key (release manifest signing)

Generate once. The fingerprint is published in `SECURITY.md` and on the maintainer's GitHub profile.

```bash
gpg --full-generate-key   # ed25519, no expiry or 2y rotation, "Bitsummit Release Key <security@bitsummit.com>"
gpg --armor --export <FINGERPRINT> > release-key.asc
gpg --keyserver hkps://keys.openpgp.org --send-keys <FINGERPRINT>
```

Add to `release.yml` before the SHA256SUMS upload:

```yaml
- name: Sign SHA256SUMS
  env:
    GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
    GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
  run: |
    echo "$GPG_PRIVATE_KEY" | gpg --batch --import
    gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" \
        --detach-sign --armor dist/binaries/SHA256SUMS
```

The detached signature (`SHA256SUMS.asc`) is uploaded with the manifest.

### 4b. macOS Developer ID (codesign + notarize)

Requires Apple Developer Program membership and a Developer ID Application certificate exported as `.p12`.

```yaml
- name: Codesign macOS binary
  env:
    APPLE_CERT_P12: ${{ secrets.APPLE_CERT_P12 }}
    APPLE_CERT_PASSWORD: ${{ secrets.APPLE_CERT_PASSWORD }}
    APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
    APPLE_ID: ${{ secrets.APPLE_ID }}
    APPLE_APP_SPECIFIC_PASSWORD: ${{ secrets.APPLE_APP_SPECIFIC_PASSWORD }}
  run: |
    # ... import p12 into a keychain, codesign --options runtime, then notarize via xcrun notarytool ...
    codesign --force --options runtime --sign "$APPLE_TEAM_ID" dist/binaries/ccsec-macos-arm64
    xcrun notarytool submit dist/binaries/ccsec-macos-arm64 \
      --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
      --password "$APPLE_APP_SPECIFIC_PASSWORD" --wait
```

### 4c. Windows Authenticode

Requires an EV (Extended Validation) code-signing certificate from a recognized CA (DigiCert, Sectigo, etc.). EV is necessary to avoid the SmartScreen warning on first run.

```yaml
- name: Sign Windows binary
  env:
    WINDOWS_CERT_PFX: ${{ secrets.WINDOWS_CERT_PFX }}
    WINDOWS_CERT_PASSWORD: ${{ secrets.WINDOWS_CERT_PASSWORD }}
  shell: pwsh
  run: |
    # ... decode pfx, signtool sign with /tr timestamp ...
    signtool sign /f cert.pfx /p $env:WINDOWS_CERT_PASSWORD `
      /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
      dist/binaries/ccsec-windows-x64.exe
```

### 4d. Secrets the maintainer must provision

| Secret | Used for | Where |
|---|---|---|
| `NPM_TOKEN` | `npm publish` | repo settings -> Secrets |
| `GPG_PRIVATE_KEY` + `GPG_PASSPHRASE` | sign `SHA256SUMS` | repo settings -> Secrets |
| `APPLE_CERT_P12` + `APPLE_CERT_PASSWORD` + `APPLE_TEAM_ID` + `APPLE_ID` + `APPLE_APP_SPECIFIC_PASSWORD` | macOS codesign + notarize | repo settings -> Secrets |
| `WINDOWS_CERT_PFX` + `WINDOWS_CERT_PASSWORD` | Authenticode | repo settings -> Secrets |

## 5. Post-Release Verification

After the workflow completes:

```bash
# 1. Verify the npm package is live with provenance.
npm view @bitsummit/claude-code-security version
npm view @bitsummit/claude-code-security dist-tags
gh release view vX.Y.Z

# 2. Verify SBOM attached.
gh release download vX.Y.Z -p sbom.cyclonedx.json -D /tmp/release-X.Y.Z
jq '.metadata.component.name' /tmp/release-X.Y.Z/sbom.cyclonedx.json

# 3. Verify SHA256SUMS matches binaries.
gh release download vX.Y.Z -p 'ccsec-*' -p SHA256SUMS -D /tmp/release-X.Y.Z
cd /tmp/release-X.Y.Z && shasum -a 256 -c SHA256SUMS

# 4. (After PGP key is provisioned) Verify signature.
gpg --verify SHA256SUMS.asc SHA256SUMS

# 5. Smoke test the binary on each platform.
./ccsec-macos-arm64 doctor
./ccsec-macos-arm64 --version
```

Smoke tests are platform-specific; run on the target OS.

## 6. Security Advisory Pipeline

When a vulnerability is reported via GHSA or `security@bitsummit.com`:

1. **Acknowledge within 72h.** Reply to the reporter, assign a triage owner, and open the GHSA in the repo's Security tab if it didn't originate there. GHSA gives us a private fork for the fix.
2. **Triage.** Assign severity (CVSS 4.0; CRITICAL / HIGH / MEDIUM / LOW), confirm reproducibility, and identify the affected versions. Use `.github/security-advisory-template.md` for the GHSA body.
3. **Private fix branch.** GHSA exposes a "Start a temporary private fork" button; use it. Fix on the private fork, NOT on `main`.
4. **CI on the private fork.** GitHub runs Actions on private GHSA forks if the repo's Actions are enabled for forks. Ensure the test suite passes.
5. **Coordinated disclosure.** Agree on a publish date with the reporter (default 90 days from ack, sooner if the reporter prefers). Cut a patch release on the publish date.
6. **Publish GHSA + release.** On publish day: merge the private fork, tag the patch release, run `release.yml`, then click "Publish advisory" on the GHSA. The GHSA links to the patch tag and the fix commit.
7. **Hall of Thanks.** Add the reporter (with permission) to `SECURITY.md`.
8. **Threat model + tests.** Add a regression test that fails on the unpatched code; add the threat to `docs/threat-model.md` if it represents a new threat ID; update `docs/known-bypasses.md` if the report exposed a previously-undocumented gap.

The advisory template is at `.github/security-advisory-template.md`.

## 7. Backports Across release/v1.x

Once `v1.0.0` ships, we maintain a `release/v1.x` branch for security backports. The policy:

- Security fixes (severity HIGH or above) backport to the latest minor of the most recent supported major.
- We support the most recent major (`v1.x`) for 12 months after `v2.0.0` ships.
- Backports use cherry-pick: `git checkout release/v1.x && git cherry-pick <fix-commit>`.
- Backport releases get a patch bump on the v1 line (e.g., `v1.4.3` -> `v1.4.4`). The `release.yml` workflow runs identically, parameterized by the tag.

A `release/v1.x` branch will be created when `v1.0.0` is cut.

---

## Appendix: Tooling Reference

- `@cyclonedx/cyclonedx-npm@2`: SBOM generation. <https://github.com/CycloneDX/cyclonedx-node-npm>
- `softprops/action-gh-release@v2`: GitHub release asset upload. <https://github.com/softprops/action-gh-release>
- `postject`: SEA blob injection. <https://github.com/nodejs/postject>
- Node SEA reference: <https://nodejs.org/api/single-executable-applications.html>
- Apple notarytool: <https://developer.apple.com/documentation/security/customizing_the_notarization_workflow>
- Authenticode signing: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/authenticode>
