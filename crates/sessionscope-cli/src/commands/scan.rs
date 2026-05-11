use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use sessionscope_classifier::classify;
use sessionscope_core::{ScanConfig, scan_path};
use sessionscope_detectors::DetectorRegistry;
use sessionscope_reporters::{ReportFormat, render};

use crate::commands::CommandResult;

pub fn run(args: &[String]) -> CommandResult {
    let mut path = PathBuf::from(".");
    let mut format = ReportFormat::Markdown;
    let mut output = None;
    let mut include_patterns = Vec::new();
    let mut exclude_patterns = Vec::new();
    let mut max_file_size_bytes = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--path" => {
                index += 1;
                path = PathBuf::from(required_value(args, index, "--path")?);
            }
            "--format" => {
                index += 1;
                format = ReportFormat::parse(required_value(args, index, "--format")?)?;
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

    let mut config = ScanConfig::new(path);
    if !include_patterns.is_empty() {
        config.set_include_patterns(include_patterns);
    }
    if !exclude_patterns.is_empty() {
        config.add_exclude_patterns(exclude_patterns);
    }
    if let Some(max_file_size_bytes) = max_file_size_bytes {
        config.set_max_file_size_bytes(max_file_size_bytes);
    }

    let registry = Arc::new(DetectorRegistry::empty());
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
