#!/usr/bin/env bats

setup() {
  TMPHOME="$(mktemp -d)"
  export FAKE_CLAUDE_DIR="${TMPHOME}/.claude"
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
  (cd "${REPO_ROOT}" && pnpm -r build >/dev/null 2>&1) || true
}
teardown() { rm -rf "${TMPHOME}"; }

@test "install.sh writes settings.json into target claude-dir" {
  run "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}"
  [ "$status" -eq 0 ]
  [ -f "${FAKE_CLAUDE_DIR}/settings.json" ]
  [ -f "${FAKE_CLAUDE_DIR}/.ccsec-lock.json" ]
}

@test "install.sh --dry-run writes nothing" {
  run "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}" --dry-run
  [ "$status" -eq 0 ]
  [ ! -f "${FAKE_CLAUDE_DIR}/settings.json" ]
}

@test "verify.sh reports OK after install" {
  "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}"
  run "${BATS_TEST_DIRNAME}/../verify.sh" --claude-dir "${FAKE_CLAUDE_DIR}"
  [ "$status" -eq 0 ]
  [[ "${output}" == *"OK"* ]]
}

@test "verify.sh fails after settings.json is tampered" {
  "${BATS_TEST_DIRNAME}/../install.sh" --profile baseline --claude-dir "${FAKE_CLAUDE_DIR}"
  echo '{"permissions":{"deny":[]}}' > "${FAKE_CLAUDE_DIR}/settings.json"
  run "${BATS_TEST_DIRNAME}/../verify.sh" --claude-dir "${FAKE_CLAUDE_DIR}"
  [ "$status" -ne 0 ]
}
