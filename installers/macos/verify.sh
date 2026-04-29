#!/usr/bin/env bash
set -euo pipefail
CLAUDE_DIR="${HOME}/.claude"
[[ "${1:-}" == "--claude-dir" ]] && CLAUDE_DIR="$2"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
node "${REPO_ROOT}/packages/cli/bin/ccsec.js" doctor --claude-dir "${CLAUDE_DIR}"
