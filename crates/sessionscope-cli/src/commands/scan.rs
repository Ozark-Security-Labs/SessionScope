use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use sessionscope_classifier::classify;
use sessionscope_core::{ScanConfig, scan_path};
use sessionscope_detectors::DetectorRegistry;
use sessionscope_reporters::{ReportFormat, render};

use crate::commands::CommandResult;
use crate::project_config::ProjectConfig;

pub fn run(args: &[String]) -> CommandResult {
    let mut path = None;
    let mut format = None;
    let mut output = None;
    let mut include_patterns = Vec::new();
    let mut exclude_patterns = Vec::new();
    let mut max_file_size_bytes = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--path" => {
                index += 1;
                path = Some(PathBuf::from(required_value(args, index, "--path")?));
            }
            "--format" => {
                index += 1;
                format = Some(ReportFormat::parse(required_value(
                    args, index, "--format",
                )?)?);
            }
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(required_value(args, index, "--output")?));
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
            _ => return Err("unknown scan option; run `sessionscope --help`".into()),
        }

        index += 1;
    }

    let project_config = ProjectConfig::load_default()?;
    let scan_root = path
        .or_else(|| project_config.first_scan_path().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    let format = format
        .or(project_config.first_format()?)
        .unwrap_or(ReportFormat::Markdown);

    let mut config = ScanConfig::new(scan_root);
    if let Some(config_include) = project_config.include {
        config.set_include_patterns(config_include);
    }
    if let Some(config_exclude) = project_config.exclude {
        config.add_exclude_patterns(config_exclude);
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

    let registry = Arc::new(DetectorRegistry::builtin());
    let report = classify(scan_path(config, registry)?);
    let rendered = render(&report, format);

    if let Some(output) = output {
        fs::write(output, rendered)?;
    } else {
        print!("{rendered}");
    }

    Ok(())
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
