#!/usr/bin/env bash
# Build Node SEA (Single-Executable Application) binary for the ccsec CLI.
#
# Usage: ./scripts/build-sea.sh [target]
#   target: macos-arm64 | macos-x64 | linux-x64 | windows-x64
#           (auto-detected if not supplied)
#
# Outputs: dist/binaries/ccsec-<target>[.exe]
# Requires: node >= 20.10, esbuild + postject (fetched via npx).
#
# Reference: https://nodejs.org/api/single-executable-applications.html

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO_ROOT/dist/binaries"
mkdir -p "$DIST"

# --- Resolve target --------------------------------------------------------
TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  case "$(uname -s)" in
    Darwin)
      case "$(uname -m)" in
        arm64)        TARGET="macos-arm64" ;;
        x86_64)       TARGET="macos-x64" ;;
        *)            TARGET="macos-$(uname -m)" ;;
      esac
      ;;
    Linux)
      case "$(uname -m)" in
        x86_64)       TARGET="linux-x64" ;;
        aarch64)      TARGET="linux-arm64" ;;
        *)            TARGET="linux-$(uname -m)" ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*) TARGET="windows-x64" ;;
    *)                    TARGET="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)" ;;
  esac
fi

EXT=""
case "$TARGET" in
  windows-*) EXT=".exe" ;;
esac
NAME="ccsec-${TARGET}${EXT}"
OUT="$DIST/$NAME"

echo "[build-sea] target=$TARGET output=$OUT"

# --- Bundle CLI to a single CJS file ---------------------------------------
cd "$REPO_ROOT"
npx --yes esbuild@0.20 \
  packages/cli/dist/index.js \
  --bundle \
  --platform=node \
  --target=node20 \
  --format=cjs \
  --outfile="$DIST/ccsec.bundle.cjs" \
  --external:./node-sea-stub-please-ignore   # placeholder for future SEA-only externals

# Tiny entry shim that the SEA blob will execute. It calls main(argv).
cat > "$DIST/ccsec.entry.cjs" <<'EOF'
const { main } = require('./ccsec.bundle.cjs');
const argv = ['node', 'ccsec', ...process.argv.slice(1)];
Promise.resolve(main(argv)).catch((err) => {
  console.error(err && err.stack || err);
  process.exit(1);
});
EOF

# --- SEA configuration -----------------------------------------------------
cat > "$DIST/sea-config.json" <<EOF
{
  "main": "$DIST/ccsec.entry.cjs",
  "output": "$DIST/sea-prep.blob",
  "disableExperimentalSEAWarning": true
}
EOF

# --- Generate SEA blob -----------------------------------------------------
node --experimental-sea-config "$DIST/sea-config.json"

# --- Copy node + inject blob ----------------------------------------------
NODE_BIN="$(command -v node)"
cp "$NODE_BIN" "$OUT"

# postject sentinel fuse is fixed by Node; do NOT change.
SENTINEL="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"

# On macOS, codesign --remove-signature is needed before postject; on Linux/Windows the strip is unnecessary.
case "$TARGET" in
  macos-*)
    if command -v codesign >/dev/null 2>&1; then
      codesign --remove-signature "$OUT" || true
    fi
    npx --yes postject@1 "$OUT" NODE_SEA_BLOB "$DIST/sea-prep.blob" \
      --sentinel-fuse "$SENTINEL" \
      --macho-segment-name NODE_SEA
    ;;
  windows-*)
    npx --yes postject@1 "$OUT" NODE_SEA_BLOB "$DIST/sea-prep.blob" \
      --sentinel-fuse "$SENTINEL"
    ;;
  *)
    npx --yes postject@1 "$OUT" NODE_SEA_BLOB "$DIST/sea-prep.blob" \
      --sentinel-fuse "$SENTINEL"
    ;;
esac

chmod +x "$OUT" || true
ls -lh "$OUT"
echo "[build-sea] built $OUT"
