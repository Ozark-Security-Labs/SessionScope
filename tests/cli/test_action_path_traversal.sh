#!/usr/bin/env bash
# F-04 regression test: scripts/github-action.sh must refuse a `path`
# input that escapes $GITHUB_WORKSPACE.
#
# Each scenario runs the action script in a sandbox with a hostile
# INPUT_PATH and asserts the script exits with status 2 (the script's
# documented usage-error code) and that the rejection message names
# the offending input.
#
# Usage:
#   tests/cli/test_action_path_traversal.sh
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
action_script="$repo_root/scripts/github-action.sh"

if [[ ! -x "$action_script" ]]; then
  chmod +x "$action_script"
fi

workspace="$(mktemp -d -t sessionscope-action-XXXXXXXX)"
trap 'rm -rf "$workspace"' EXIT

run_case() {
  local description="$1"
  local input_path="$2"

  set +e
  output="$(
    GITHUB_WORKSPACE="$workspace" \
    RUNNER_TEMP="$workspace/runner" \
    INPUT_MODE="advisory" \
    INPUT_PATH="$input_path" \
    INPUT_OUTPUT="markdown" \
    INPUT_FAIL_ON_FINDINGS="false" \
    INPUT_FAIL_SEVERITY="high" \
    SESSIONSCOPE_BIN="/bin/true" \
    "$action_script" 2>&1
  )"
  status=$?
  set -e

  if [[ "$status" -ne 2 ]]; then
    echo "FAIL: $description"
    echo "  expected exit 2, got $status"
    echo "  output: $output"
    exit 1
  fi
  echo "ok: $description (input=$input_path)"
}

run_case "rejects ../etc traversal" "../etc"
run_case "rejects nested .. traversal" "foo/../../etc"
run_case "rejects absolute path"     "/etc/passwd"
run_case "rejects trailing .."       "foo/.."

echo "all F-04 path-traversal cases rejected as expected"
