use std::fs;
use std::path::PathBuf;

use sessionscope_core::redaction::sanitized_report;
use sessionscope_model::ScanReport;

use crate::commands::CommandResult;
use crate::commands::policy::{
    EnforcementOverrides, build_enforcement_options, load_project_config,
};
use crate::enforcement::{
    PolicyMode, format_failure, parse_category, parse_mode, parse_severity, split_values,
};

pub fn run(args: &[String]) -> CommandResult {
    let (report_path, args) = args
        .split_first()
        .ok_or_else(|| "missing report path for evaluate".to_string())?;

    let mut mode = None;
    let mut fail_severity = None;
    let mut fail_categories = Vec::new();
    let mut include_finding_ids = Vec::new();
    let mut exclude_finding_ids = Vec::new();
    let mut baseline = None;
    let mut use_policy_config = true;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--mode" => {
                index += 1;
                mode = Some(parse_mode(required_value(args, index, "--mode")?)?);
            }
            "--fail-severity" => {
                index += 1;
                fail_severity = Some(parse_severity(required_value(
                    args,
                    index,
                    "--fail-severity",
                )?)?);
            }
            "--fail-category" => {
                index += 1;
                for category in split_values(required_value(args, index, "--fail-category")?) {
                    fail_categories.push(parse_category(&category)?);
                }
            }
            "--include-finding-id" => {
                index += 1;
                include_finding_ids.extend(split_values(required_value(
                    args,
                    index,
                    "--include-finding-id",
                )?));
            }
            "--exclude-finding-id" => {
                index += 1;
                exclude_finding_ids.extend(split_values(required_value(
                    args,
                    index,
                    "--exclude-finding-id",
                )?));
            }
            "--baseline" => {
                index += 1;
                // Mirror scan's `--baseline -- VALUE` support so the GitHub
                // Action wrapper can pass baseline paths defensively.
                baseline = Some(PathBuf::from(parse_terminated_value(
                    args,
                    &mut index,
                    "--baseline",
                )?));
            }
            // Action-internal: skip merging sessionscope.toml policy into the
            // evaluate run. Mirrors the same flag on `scan`. Intentionally
            // omitted from --help.
            "--no-policy-config" => {
                use_policy_config = false;
            }
            _ => return Err("unknown evaluate option; run `sessionscope --help`".into()),
        }
        index += 1;
    }

    let project_config = load_project_config(use_policy_config)?;
    let options = build_enforcement_options(
        &project_config,
        EnforcementOverrides {
            mode,
            fail_severity,
            fail_categories,
            include_finding_ids,
            exclude_finding_ids,
            baseline,
            use_policy_config,
        },
    )?;

    let contents = fs::read_to_string(report_path)
        .map_err(|error| format!("failed to read scan report {report_path}: {error}"))?;
    let report: ScanReport = serde_json::from_str(&contents)
        .map_err(|_| format!("failed to parse scan report {report_path} as JSON"))?;
    let sanitized = sanitized_report(&report);
    let result = options.evaluate(&sanitized)?;
    if options.mode == PolicyMode::Enforce && !result.blocking_findings.is_empty() {
        return Err(format_failure(&result).into());
    }

    Ok(())
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))
}

/// Mirror of `scan::parse_terminated_value`. See that function for the
/// rationale; in short, consume an optional `--` before reading the value for
/// `flag` so the github-action wrapper can pass `--baseline -- VALUE`.
fn parse_terminated_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, String> {
    if args.get(*index).map(String::as_str) == Some("--") {
        *index += 1;
    }
    let value = required_value(args, *index, flag)?.to_string();
    Ok(value)
}
