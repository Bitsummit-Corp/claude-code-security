#!/usr/bin/env bash
set -euo pipefail

PROFILE="baseline"
CLAUDE_DIR="${HOME}/.claude"
DRY_RUN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)    PROFILE="$2"; shift 2 ;;
    --claude-dir) CLAUDE_DIR="$2"; shift 2 ;;
    --dry-run)    DRY_RUN="--dry-run"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "error: node not found in PATH; install Node >=20.10" >&2
  exit 3
fi

echo "ccsec macOS installer: profile=${PROFILE} claude_dir=${CLAUDE_DIR}"

if [[ ! -f "${REPO_ROOT}/packages/cli/dist/index.js" ]]; then
  echo "building ccsec from source..."
  (cd "${REPO_ROOT}" && pnpm install && pnpm -r build)
fi

node "${REPO_ROOT}/packages/cli/bin/ccsec.js" apply \
  --profile "${PROFILE}" \
  --claude-dir "${CLAUDE_DIR}" \
  --os macos \
  --settings-root "${REPO_ROOT}/packages/settings" \
  ${DRY_RUN}

echo "done."
