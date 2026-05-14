#!/usr/bin/env bash
set -euo pipefail

mode="${INPUT_MODE:-advisory}"
scan_path="${INPUT_PATH:-.}"
outputs="${INPUT_OUTPUT:-markdown,sarif}"
fail_on_findings="${INPUT_FAIL_ON_FINDINGS:-false}"
reports_dir="${SESSIONSCOPE_REPORTS_DIR:-${RUNNER_TEMP:-/tmp}/sessionscope-reports}"
summary_path="$reports_dir/summary.md"

case "$mode" in
  advisory) ;;
  *)
    echo "sessionscope: unsupported mode '$mode'; only advisory is supported" >&2
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
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  fi
}

validate_requested_formats

json_path="$reports_dir/sessionscope.json"
run_sessionscope scan --path "$scan_path" --format json --output "$json_path"

markdown_path=""
sarif_path=""
if format_requested markdown; then
  markdown_path="$reports_dir/sessionscope.md"
  run_sessionscope scan --path "$scan_path" --format markdown --output "$markdown_path"
fi
if format_requested json; then
  # The internal JSON report is also the requested JSON artifact.
  :
fi
if format_requested sarif; then
  sarif_path="$reports_dir/sessionscope.sarif"
  run_sessionscope scan --path "$scan_path" --format sarif --output "$sarif_path"
fi

python3 - "$json_path" "$summary_path" "$reports_dir" "$markdown_path" "$sarif_path" <<'PY'
import json
import sys
from pathlib import Path

json_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
reports_dir = sys.argv[3]
markdown_path = sys.argv[4]
sarif_path = sys.argv[5]

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
    f"- Reports directory: `{reports_dir}`",
    f"- JSON: `{json_path}`",
])
if markdown_path:
    lines.append(f"- Markdown: `{markdown_path}`")
if sarif_path:
    lines.append(f"- SARIF: `{sarif_path}`")
lines.append("")

summary_path.write_text("\n".join(lines))
PY

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$summary_path" >> "$GITHUB_STEP_SUMMARY"
fi

finding_count="$(python3 - "$json_path" <<'PY'
import json
import sys
print(len(json.loads(open(sys.argv[1]).read()).get("findings", [])))
PY
)"

write_output reports-dir "$reports_dir"
write_output json-path "$json_path"
write_output summary-path "$summary_path"
if [[ -n "$markdown_path" ]]; then
  write_output markdown-path "$markdown_path"
fi
if [[ -n "$sarif_path" ]]; then
  write_output sarif-path "$sarif_path"
fi

if [[ "$fail_on_findings" == "true" && "$finding_count" != "0" ]]; then
  echo "sessionscope: found $finding_count finding(s)" >&2
  exit 1
fi
