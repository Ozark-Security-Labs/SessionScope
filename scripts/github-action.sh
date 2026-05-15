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

mkdir -p "$reports_dir"

run_sessionscope() {
  if [[ -n "${SESSIONSCOPE_BIN:-}" ]]; then
    "$SESSIONSCOPE_BIN" "$@"
  else
    cargo run --quiet --manifest-path "$GITHUB_ACTION_PATH/Cargo.toml" -p sessionscope-cli -- "$@"
  fi
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

remove_internal_json() {
  if [[ "${json_requested:-false}" != "true" && -n "${json_path:-}" ]]; then
    rm -f "$json_path"
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
  json_path="$(mktemp "${RUNNER_TEMP:-/tmp}/sessionscope-json.XXXXXX")"
  trap remove_internal_json EXIT
fi

run_sessionscope scan --path "$scan_path" --no-policy-config --mode advisory "${policy_args[@]}" --format json --output "$json_path"

markdown_path=""
sarif_path=""
if format_requested markdown; then
  markdown_path="$reports_dir/sessionscope.md"
  run_sessionscope scan --path "$scan_path" --no-policy-config --mode advisory "${policy_args[@]}" --format markdown --output "$markdown_path"
fi
if format_requested sarif; then
  sarif_path="$reports_dir/sessionscope.sarif"
  run_sessionscope scan --path "$scan_path" --no-policy-config --mode advisory "${policy_args[@]}" --format sarif --output "$sarif_path"
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
  enforcement_path="$(mktemp "${RUNNER_TEMP:-/tmp}/sessionscope-enforcement.XXXXXX")"
  run_sessionscope scan \
    --path "$scan_path" \
    --no-policy-config \
    --mode enforce \
    --fail-severity "$effective_fail_severity" \
    "${policy_args_without_severity[@]}" \
    --format json \
    --output "$enforcement_path"
fi
