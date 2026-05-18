#!/usr/bin/env bash
set -euo pipefail

mode="${INPUT_MODE:-advisory}"
scan_path="${INPUT_PATH:-.}"
outputs="${INPUT_OUTPUT:-markdown,sarif}"
fail_on_findings="${INPUT_FAIL_ON_FINDINGS:-false}"
fail_severity="${INPUT_FAIL_SEVERITY:-high}"
fail_category="${INPUT_FAIL_CATEGORY:-}"
include_finding_id="${INPUT_INCLUDE_FINDING_ID:-}"
exclude_finding_id="${INPUT_EXCLUDE_FINDING_ID:-}"
baseline="${INPUT_BASELINE:-}"
reports_dir="${SESSIONSCOPE_REPORTS_DIR:-${RUNNER_TEMP:-/tmp}/sessionscope-reports}"
summary_path="$reports_dir/summary.md"

case "$mode" in
  advisory | enforce) ;;
  *)
    echo "sessionscope: mode must be advisory or enforce" >&2
    exit 2
    ;;
esac

case "$fail_on_findings" in
  true | false) ;;
  *)
    echo "sessionscope: fail-on-findings must be true or false" >&2
    exit 2
    ;;
esac

case "$scan_path" in
  /*)
    echo "sessionscope: path must be repository-relative, got '$scan_path'" >&2
    exit 2
    ;;
esac

mkdir -p "$reports_dir"

cleanup_internal_artifacts() {
  # Preserve the triggering exit code. Bash 3.x (macOS default) lets a
  # successful EXIT trap mask a failing script exit code unless we exit
  # explicitly with the saved status.
  local exit_code=$?
  if [[ "${json_requested:-false}" != "true" && -n "${json_path:-}" ]]; then
    rm -f "$json_path"
  fi
  if [[ -n "${enforcement_path:-}" ]]; then
    rm -f "$enforcement_path"
  fi
  exit "$exit_code"
}
trap cleanup_internal_artifacts EXIT

run_sessionscope() {
  if [[ -n "${SESSIONSCOPE_BIN:-}" ]]; then
    "$SESSIONSCOPE_BIN" "$@"
  else
    cargo run --quiet --manifest-path "$GITHUB_ACTION_PATH/Cargo.toml" -p sessionscope-cli -- "$@"
  fi
}

release_artifact_for_runner() {
  local version="$1"
  local host=""
  local archive=""
  local binary="sessionscope"

  case "${RUNNER_OS:-}:${RUNNER_ARCH:-}" in
    Linux:X64)
      host="x86_64-unknown-linux-gnu"
      archive="sessionscope-${version}-${host}.tar.gz"
      ;;
    Linux:ARM64)
      host="aarch64-unknown-linux-gnu"
      archive="sessionscope-${version}-${host}.tar.gz"
      ;;
    macOS:X64)
      host="x86_64-apple-darwin"
      archive="sessionscope-${version}-${host}.tar.gz"
      ;;
    macOS:ARM64)
      host="aarch64-apple-darwin"
      archive="sessionscope-${version}-${host}.tar.gz"
      ;;
    Windows:X64)
      host="x86_64-pc-windows-msvc"
      archive="sessionscope-${version}-${host}.zip"
      binary="sessionscope.exe"
      ;;
    *)
      return 1
      ;;
  esac

  printf '%s\t%s\n' "$archive" "$binary"
}

verify_checksum() {
  local checksum_file="$1"
  local checksum_dir
  checksum_dir="$(dirname "$checksum_file")"
  local checksum_name
  checksum_name="$(basename "$checksum_file")"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$checksum_dir" && sha256sum -c "$checksum_name")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$checksum_dir" && shasum -a 256 -c "$checksum_name")
  else
    echo "sessionscope: no SHA-256 verifier found; falling back to cargo run" >&2
    return 1
  fi
}

resolve_release_binary() {
  if [[ -n "${SESSIONSCOPE_BIN:-}" ]]; then
    return 0
  fi

  local action_ref="${GITHUB_ACTION_REF:-}"
  case "$action_ref" in
    v[0-9]*.[0-9]*.[0-9]* | v[0-9]*.[0-9]*.[0-9]*-*) ;;
    *)
      return 0
      ;;
  esac

  if ! command -v gh >/dev/null 2>&1; then
    echo "sessionscope: gh is unavailable; falling back to cargo run" >&2
    return 0
  fi

  local version="${action_ref#v}"
  local artifact_info
  if ! artifact_info="$(release_artifact_for_runner "$version")"; then
    echo "sessionscope: no release binary mapping for ${RUNNER_OS:-unknown}/${RUNNER_ARCH:-unknown}; falling back to cargo run" >&2
    return 0
  fi

  local archive="${artifact_info%%$'\t'*}"
  local binary="${artifact_info#*$'\t'}"
  local download_dir
  download_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/sessionscope-release.XXXXXX")"
  local repository="${GITHUB_ACTION_REPOSITORY:-Ozark-Security-Labs/SessionScope}"

  if ! gh release download "$action_ref" -R "$repository" -p "$archive" -p "$archive.sha256" --dir "$download_dir"; then
    echo "sessionscope: release binary ${archive} unavailable; falling back to cargo run" >&2
    return 0
  fi
  if ! verify_checksum "$download_dir/$archive.sha256"; then
    return 0
  fi

  local extract_dir="$download_dir/extract"
  mkdir -p "$extract_dir"
  case "$archive" in
    *.zip)
      if ! unzip -q "$download_dir/$archive" -d "$extract_dir"; then
        echo "sessionscope: failed to extract ${archive}; falling back to cargo run" >&2
        return 0
      fi
      ;;
    *.tar.gz)
      if ! tar -C "$extract_dir" -xzf "$download_dir/$archive"; then
        echo "sessionscope: failed to extract ${archive}; falling back to cargo run" >&2
        return 0
      fi
      ;;
    *)
      echo "sessionscope: unsupported release archive ${archive}; falling back to cargo run" >&2
      return 0
      ;;
  esac

  local resolved_bin
  resolved_bin="$(find "$extract_dir" -name "$binary" -type f | head -n 1)"
  if [[ -z "$resolved_bin" ]]; then
    echo "sessionscope: release archive did not contain ${binary}; falling back to cargo run" >&2
    return 0
  fi
  if [[ "${RUNNER_OS:-}" != "Windows" ]]; then
    chmod +x "$resolved_bin"
  fi
  SESSIONSCOPE_BIN="$resolved_bin"
  export SESSIONSCOPE_BIN
}

format_requested() {
  local requested="$1"
  IFS=',' read -ra formats <<< "$outputs"
  for raw_format in "${formats[@]}"; do
    local format
    format="$(echo "$raw_format" | tr -d '[:space:]')"
    if [[ "$format" == "$requested" ]]; then
      return 0
    fi
  done
  return 1
}

validate_requested_formats() {
  IFS=',' read -ra formats <<< "$outputs"
  for raw_format in "${formats[@]}"; do
    local format
    format="$(echo "$raw_format" | tr -d '[:space:]')"
    case "$format" in
      markdown | json | sarif) ;;
      "")
        echo "sessionscope: output contains an empty format" >&2
        exit 2
        ;;
      *)
        echo "sessionscope: unsupported output format '$format'; expected markdown, json, or sarif" >&2
        exit 2
        ;;
    esac
  done
}

write_output() {
  local name="$1"
  local value="$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    local delimiter="sessionscope_${name}_$$_${RANDOM}"
    {
      printf '%s<<%s\n' "$name" "$delimiter"
      printf '%s\n' "$value"
      printf '%s\n' "$delimiter"
    } >> "$GITHUB_OUTPUT"
  fi
}

prefix_sarif_uris() {
  local sarif_file="$1"
  local prefix="$2"
  python3 - "$sarif_file" "$prefix" <<'PY'
import json
import sys
from pathlib import PurePosixPath

sarif_path = sys.argv[1]
raw_prefix = sys.argv[2].replace("\\", "/")

if raw_prefix.startswith("/"):
    sys.exit(0)

prefix_parts = [part for part in raw_prefix.split("/") if part not in ("", ".")]
if not prefix_parts:
    sys.exit(0)

prefix = str(PurePosixPath(*prefix_parts))

with open(sarif_path, encoding="utf-8") as handle:
    sarif = json.load(handle)

for run in sarif.get("runs", []):
    for result in run.get("results", []):
        for location in result.get("locations", []):
            artifact = (
                location
                .get("physicalLocation", {})
                .get("artifactLocation", {})
            )
            uri = artifact.get("uri")
            if (
                isinstance(uri, str)
                and uri
                and not uri.startswith("/")
                and "://" not in uri
                and uri != prefix
                and not uri.startswith(prefix + "/")
            ):
                artifact["uri"] = f"{prefix}/{uri}"

with open(sarif_path, "w", encoding="utf-8") as handle:
    json.dump(sarif, handle, indent=2)
    handle.write("\n")
PY
}

validate_requested_formats
resolve_release_binary

# Bash 3.x (macOS default) treats "${arr[@]}" as unbound when arr is empty
# under `set -u`. Expansions of these arrays below use the
# `${arr[@]+"${arr[@]}"}` pattern, which expands to nothing when the array
# is unset/empty and to the quoted elements otherwise. Do not "tidy" those
# expansions back to the simpler form.
policy_args=()
policy_args_without_severity=()
if [[ -n "$fail_severity" ]]; then
  policy_args+=(--fail-severity "$fail_severity")
fi
if [[ -n "$fail_category" ]]; then
  policy_args+=(--fail-category "$fail_category")
  policy_args_without_severity+=(--fail-category "$fail_category")
fi
if [[ -n "$include_finding_id" ]]; then
  policy_args+=(--include-finding-id "$include_finding_id")
  policy_args_without_severity+=(--include-finding-id "$include_finding_id")
fi
if [[ -n "$exclude_finding_id" ]]; then
  policy_args+=(--exclude-finding-id "$exclude_finding_id")
  policy_args_without_severity+=(--exclude-finding-id "$exclude_finding_id")
fi
if [[ -n "$baseline" ]]; then
  policy_args+=(--baseline "$baseline")
  policy_args_without_severity+=(--baseline "$baseline")
fi

json_requested=false
if format_requested json; then
  json_requested=true
  json_path="$reports_dir/sessionscope.json"
else
  json_path="$reports_dir/sessionscope.json"
fi

markdown_path=""
sarif_path=""
if format_requested markdown; then
  markdown_path="$reports_dir/sessionscope.md"
fi
if format_requested sarif; then
  sarif_path="$reports_dir/sessionscope.sarif"
fi

scan_outputs="$outputs"
if [[ "$json_requested" != "true" ]]; then
  scan_outputs="${scan_outputs},json"
fi

run_sessionscope scan --path "$scan_path" --no-policy-config --mode advisory ${policy_args[@]+"${policy_args[@]}"} --format "$scan_outputs" --output-dir "$reports_dir"

if [[ -n "$sarif_path" ]]; then
  prefix_sarif_uris "$sarif_path" "$scan_path"
fi

python3 - "$json_path" "$summary_path" "$reports_dir" "$markdown_path" "$sarif_path" "$json_requested" <<'PY'
import json
import sys
from pathlib import Path

json_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
reports_dir = sys.argv[3]
markdown_path = sys.argv[4]
sarif_path = sys.argv[5]
json_requested = sys.argv[6] == "true"

report = json.loads(json_path.read_text())
summary = report.get("summary", {})
findings = report.get("findings", [])
lifecycle_paths = report.get("lifecycle_paths", [])

def inline_text(value):
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )

lines = [
    "## SessionScope",
    "",
    "| Metric | Count |",
    "| --- | ---: |",
    f"| Files discovered | {summary.get('files_discovered', 0)} |",
    f"| Files scanned | {summary.get('files_scanned', 0)} |",
    f"| Files skipped | {summary.get('files_skipped', 0)} |",
    f"| Lifecycle paths | {len(lifecycle_paths)} |",
    f"| Findings | {len(findings)} |",
    "",
]

if findings:
    lines.extend(["### Key findings", ""])
    for finding in findings[:5]:
        title = inline_text(finding.get("title", "Untitled finding"))
        severity = finding.get("severity", "unknown")
        category = finding.get("category", "unknown")
        lines.append(f"- `{severity}` `{category}` {title}")
    if len(findings) > 5:
        lines.append(f"- ...and {len(findings) - 5} more findings.")
else:
    lines.append("No findings were detected.")

lines.extend([
    "",
    "### Reports",
    "",
    f"- Reports directory: `{inline_text(reports_dir)}`",
])
if json_requested:
    lines.append(f"- JSON: `{inline_text(json_path)}`")
if markdown_path:
    lines.append(f"- Markdown: `{inline_text(markdown_path)}`")
if sarif_path:
    lines.append(f"- SARIF: `{inline_text(sarif_path)}`")
lines.append("")

summary_path.write_text("\n".join(lines))
PY

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$summary_path" >> "$GITHUB_STEP_SUMMARY"
fi

write_output reports-dir "$reports_dir"
write_output summary-path "$summary_path"
if [[ "$json_requested" == "true" ]]; then
  write_output json-path "$json_path"
fi
if [[ -n "$markdown_path" ]]; then
  write_output markdown-path "$markdown_path"
fi
if [[ -n "$sarif_path" ]]; then
  write_output sarif-path "$sarif_path"
fi

effective_mode="$mode"
effective_fail_severity="$fail_severity"
if [[ "$fail_on_findings" == "true" ]]; then
  effective_mode="enforce"
  effective_fail_severity="info"
fi

if [[ "$effective_mode" == "enforce" ]]; then
  # Capture the enforcement status explicitly rather than relying on set -e:
  # bash 3.x (macOS) does not always propagate a function's nonzero exit
  # through an active EXIT trap, which would otherwise mask a real failure
  # here as exit 0.
  enforcement_status=0
  run_sessionscope evaluate \
    "$json_path" \
    --mode enforce \
    --fail-severity "$effective_fail_severity" \
    ${policy_args_without_severity[@]+"${policy_args_without_severity[@]}"} || enforcement_status=$?
  if [[ $enforcement_status -ne 0 ]]; then
    exit "$enforcement_status"
  fi
fi
