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
            unknown => return Err(format!("unknown scan option `{unknown}`").into()),
        }

        index += 1;
    }

    let config = ScanConfig::new(path);
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
