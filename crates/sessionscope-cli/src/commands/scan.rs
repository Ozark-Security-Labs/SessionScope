use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use sessionscope_classifier::classify;
use sessionscope_core::redaction::sanitized_report;
use sessionscope_core::{CapabilityArea, ScanConfig, filter_report, scan_path};
use sessionscope_detectors::DetectorRegistry;
use sessionscope_reporters::{ReportFormat, render};

use crate::commands::CommandResult;
use crate::enforcement::{
    EnforcementOptions, PolicyMode as EnforcementMode, format_failure, parse_category, parse_mode,
    parse_severity, split_values,
};
use crate::project_config::ProjectConfig;

pub fn run(args: &[String]) -> CommandResult {
    run_with_capability(args, None)
}

pub fn run_capability(args: &[String], capability: CapabilityArea) -> CommandResult {
    run_with_capability(args, Some(capability))
}

fn run_with_capability(args: &[String], capability: Option<CapabilityArea>) -> CommandResult {
    let mut path = None;
    let mut formats = None;
    let mut output = None;
    let mut output_dir = None;
    let mut include_patterns = Vec::new();
    let mut exclude_patterns = Vec::new();
    let mut max_file_size_bytes = None;
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
            "--path" => {
                index += 1;
                path = Some(PathBuf::from(required_value(args, index, "--path")?));
            }
            "--format" => {
                index += 1;
                let parsed = parse_formats(required_value(args, index, "--format")?)?;
                validate_capability_formats(&parsed, capability)?;
                formats = Some(parsed);
            }
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(required_value(args, index, "--output")?));
            }
            "--output-dir" => {
                index += 1;
                output_dir = Some(PathBuf::from(required_value(args, index, "--output-dir")?));
            }
            "--include" => {
                index += 1;
                include_patterns.extend(split_patterns(required_value(args, index, "--include")?));
            }
            "--exclude" => {
                index += 1;
                exclude_patterns.extend(split_patterns(required_value(args, index, "--exclude")?));
            }
            "--max-file-size" => {
                index += 1;
                max_file_size_bytes = Some(parse_max_file_size(required_value(
                    args,
                    index,
                    "--max-file-size",
                )?)?);
            }
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
                baseline = Some(PathBuf::from(required_value(args, index, "--baseline")?));
            }
            // Action-internal: keeps Action-supplied policy from being overridden by checked-in
            // TOML during PR CI. Intentionally omitted from --help. Do not remove without
            // updating scripts/github-action.sh, which depends on this flag.
            "--no-policy-config" => {
                use_policy_config = false;
            }
            _ => return Err(unknown_option_message(capability).into()),
        }

        index += 1;
    }

    let project_config = if use_policy_config {
        ProjectConfig::load_default()?
    } else {
        ProjectConfig::empty()
    };
    let scan_root = path
        .or_else(|| project_config.first_scan_path().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    let formats = match formats {
        Some(formats) => formats,
        None => vec![
            project_config
                .first_format()?
                .unwrap_or(ReportFormat::Markdown),
        ],
    };
    validate_capability_formats(&formats, capability)?;
    validate_output_options(&formats, output.as_ref(), output_dir.as_ref())?;

    let mut config = ScanConfig::new(scan_root);
    if let Some(config_include) = &project_config.include {
        config.set_include_patterns(config_include.clone());
    }
    if let Some(config_exclude) = &project_config.exclude {
        config.add_exclude_patterns(config_exclude.clone());
    }
    if let Some(config_max_file_size_bytes) = project_config.max_file_size_bytes {
        config.set_max_file_size_bytes(config_max_file_size_bytes);
    }

    if !include_patterns.is_empty() {
        config.set_include_patterns(include_patterns);
    }
    if !exclude_patterns.is_empty() {
        config.add_exclude_patterns(exclude_patterns);
    }
    if let Some(max_file_size_bytes) = max_file_size_bytes {
        config.set_max_file_size_bytes(max_file_size_bytes);
    }

    let enforcement = build_enforcement_options(
        &project_config,
        EnforcementArgs {
            mode,
            fail_severity,
            fail_categories,
            include_finding_ids,
            exclude_finding_ids,
            baseline,
            use_policy_config,
        },
    )?;

    let registry = Arc::new(DetectorRegistry::builtin());
    let mut report = classify(scan_path(config, registry)?);
    if let Some(capability) = capability {
        report = filter_report(&report, capability);
    }
    if let Some(output_dir) = output_dir {
        fs::create_dir_all(&output_dir).map_err(|error| {
            format!(
                "failed to create scan output directory {}: {error}",
                output_dir.display()
            )
        })?;
        for format in &formats {
            let rendered = render(&report, *format);
            let output_path = output_dir.join(output_filename(*format));
            fs::write(&output_path, rendered).map_err(|error| {
                format!(
                    "failed to write scan output to {}: {error}",
                    output_path.display()
                )
            })?;
        }
    } else {
        let format = formats[0];
        let rendered = render(&report, format);
        if let Some(output) = output {
            fs::write(&output, rendered).map_err(|error| {
                format!(
                    "failed to write scan output to {}: {error}",
                    output.display()
                )
            })?;
        } else {
            print!("{rendered}");
        }
    }

    let enforcement_report = sanitized_report(&report);
    let enforcement_result = enforcement.evaluate(&enforcement_report)?;
    if enforcement.mode == EnforcementMode::Enforce
        && !enforcement_result.blocking_findings.is_empty()
    {
        return Err(format_failure(&enforcement_result).into());
    }

    Ok(())
}

fn parse_formats(value: &str) -> Result<Vec<ReportFormat>, String> {
    let formats = value
        .split(',')
        .map(str::trim)
        .filter(|format| !format.is_empty())
        .map(|format| ReportFormat::parse(format).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if formats.is_empty() {
        return Err("format must include at least one report format".to_string());
    }
    Ok(formats)
}

fn validate_capability_formats(
    formats: &[ReportFormat],
    capability: Option<CapabilityArea>,
) -> Result<(), String> {
    if capability.is_some()
        && formats
            .iter()
            .any(|format| !matches!(format, ReportFormat::Json | ReportFormat::Markdown))
    {
        return Err("unsupported capability format; expected markdown or json".to_string());
    }
    Ok(())
}

fn validate_output_options(
    formats: &[ReportFormat],
    output: Option<&PathBuf>,
    output_dir: Option<&PathBuf>,
) -> Result<(), String> {
    if output.is_some() && output_dir.is_some() {
        return Err("--output and --output-dir cannot be used together".to_string());
    }
    if formats.len() > 1 && output_dir.is_none() {
        return Err("multiple formats require --output-dir".to_string());
    }
    Ok(())
}

fn output_filename(format: ReportFormat) -> &'static str {
    match format {
        ReportFormat::Json => "sessionscope.json",
        ReportFormat::Markdown => "sessionscope.md",
        ReportFormat::Sarif => "sessionscope.sarif",
        ReportFormat::GithubSummary => "sessionscope-summary.md",
    }
}

fn unknown_option_message(capability: Option<CapabilityArea>) -> &'static str {
    if capability.is_some() {
        "unknown capability option; run `sessionscope --help`"
    } else {
        "unknown scan option; run `sessionscope --help`"
    }
}

struct EnforcementArgs {
    mode: Option<EnforcementMode>,
    fail_severity: Option<sessionscope_model::Severity>,
    fail_categories: Vec<sessionscope_model::FindingCategory>,
    include_finding_ids: Vec<String>,
    exclude_finding_ids: Vec<String>,
    baseline: Option<PathBuf>,
    use_policy_config: bool,
}

fn build_enforcement_options(
    project_config: &ProjectConfig,
    args: EnforcementArgs,
) -> Result<EnforcementOptions, String> {
    let mut enforcement = EnforcementOptions::default();

    if args.use_policy_config {
        if let Some(config_mode) = project_config.mode {
            enforcement.mode = match config_mode {
                crate::project_config::PolicyMode::Advisory => EnforcementMode::Advisory,
                crate::project_config::PolicyMode::Enforce => EnforcementMode::Enforce,
            };
        }
        if let Some(config_fail_severity) = &project_config.fail_severity {
            enforcement.fail_severity = parse_severity(config_fail_severity)?;
        }
        if let Some(config_fail_categories) = &project_config.fail_categories
            && !config_fail_categories.is_empty()
        {
            enforcement.fail_categories = Some(
                config_fail_categories
                    .iter()
                    .map(|category| parse_category(category))
                    .collect::<Result<BTreeSet<_>, _>>()?,
            );
        }
        if let Some(config_include_ids) = &project_config.include_finding_ids {
            enforcement
                .include_finding_ids
                .extend(config_include_ids.iter().cloned());
        }
        if let Some(config_exclude_ids) = &project_config.exclude_finding_ids {
            enforcement
                .exclude_finding_ids
                .extend(config_exclude_ids.iter().cloned());
        }
        if let Some(config_baseline) = &project_config.baseline {
            enforcement.baseline = Some(PathBuf::from(config_baseline));
        }
    }

    if let Some(mode) = args.mode {
        enforcement.mode = mode;
    }
    if let Some(fail_severity) = args.fail_severity {
        enforcement.fail_severity = fail_severity;
    }
    if !args.fail_categories.is_empty() {
        enforcement.fail_categories = Some(args.fail_categories.into_iter().collect());
    }
    if !args.include_finding_ids.is_empty() {
        enforcement.include_finding_ids = args.include_finding_ids.into_iter().collect();
    }
    if !args.exclude_finding_ids.is_empty() {
        enforcement.exclude_finding_ids = args.exclude_finding_ids.into_iter().collect();
    }
    if let Some(baseline) = args.baseline {
        enforcement.baseline = Some(baseline);
    }

    Ok(enforcement)
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn split_patterns(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_max_file_size(value: &str) -> Result<u64, String> {
    let max_file_size_bytes = value
        .parse::<u64>()
        .map_err(|_| "max file size must be a positive integer byte count".to_string())?;

    if max_file_size_bytes == 0 {
        return Err("max file size must be greater than zero".to_string());
    }

    Ok(max_file_size_bytes)
}
