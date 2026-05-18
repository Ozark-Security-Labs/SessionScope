use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sessionscope_core::redaction::sanitized_report;
use sessionscope_model::ScanReport;

use crate::commands::CommandResult;
use crate::enforcement::{
    EnforcementOptions, PolicyMode, format_failure, parse_category, parse_mode, parse_severity,
    split_values,
};

pub fn run(args: &[String]) -> CommandResult {
    let (report_path, args) = args
        .split_first()
        .ok_or_else(|| "missing report path for evaluate".to_string())?;
    let mut options = EnforcementOptions::default();
    let mut fail_categories = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--mode" => {
                index += 1;
                options.mode = parse_mode(required_value(args, index, "--mode")?)?;
            }
            "--fail-severity" => {
                index += 1;
                options.fail_severity =
                    parse_severity(required_value(args, index, "--fail-severity")?)?;
            }
            "--fail-category" => {
                index += 1;
                for category in split_values(required_value(args, index, "--fail-category")?) {
                    fail_categories.push(parse_category(&category)?);
                }
            }
            "--include-finding-id" => {
                index += 1;
                options
                    .include_finding_ids
                    .extend(split_values(required_value(
                        args,
                        index,
                        "--include-finding-id",
                    )?));
            }
            "--exclude-finding-id" => {
                index += 1;
                options
                    .exclude_finding_ids
                    .extend(split_values(required_value(
                        args,
                        index,
                        "--exclude-finding-id",
                    )?));
            }
            "--baseline" => {
                index += 1;
                options.baseline = Some(PathBuf::from(required_value(args, index, "--baseline")?));
            }
            _ => return Err("unknown evaluate option; run `sessionscope --help`".into()),
        }
        index += 1;
    }

    if !fail_categories.is_empty() {
        options.fail_categories = Some(fail_categories.into_iter().collect::<BTreeSet<_>>());
    }

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
