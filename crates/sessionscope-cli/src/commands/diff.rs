use crate::commands::CommandResult;
use sessionscope_core::diff_baseline;
use sessionscope_model::{Baseline, ScanReport};
use sessionscope_reporters::{render_diff_json, render_diff_markdown};
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> CommandResult {
    let mut baseline = None;
    let mut current = None;
    let mut format = DiffFormat::Markdown;
    let mut output = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--baseline" => {
                index += 1;
                baseline = Some(PathBuf::from(required_value(args, index, "--baseline")?));
            }
            "--current" => {
                index += 1;
                current = Some(PathBuf::from(required_value(args, index, "--current")?));
            }
            "--format" => {
                index += 1;
                format = DiffFormat::parse(required_value(args, index, "--format")?)?;
            }
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(required_value(args, index, "--output")?));
            }
            _ => {
                return Err(
                    "usage: sessionscope diff --baseline BASELINE.json --current REPORT.json [--format json|markdown] [--output PATH]"
                        .into(),
                );
            }
        }

        index += 1;
    }

    let baseline_path = baseline.ok_or("missing --baseline BASELINE.json")?;
    let current_path = current.ok_or("missing --current REPORT.json")?;
    let baseline: Baseline = read_json(&baseline_path, "baseline")?;
    let current_report: ScanReport = read_json(&current_path, "current scan report")?;
    let diff = diff_baseline(&baseline, &current_report);
    let rendered = match format {
        DiffFormat::Json => render_diff_json(&diff),
        DiffFormat::Markdown => render_diff_markdown(&diff),
    };

    if let Some(output) = output {
        fs::write(&output, rendered).map_err(|error| {
            format!(
                "failed to write diff output to {}: {error}",
                output.display()
            )
        })?;
    } else {
        println!("{rendered}");
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffFormat {
    Json,
    Markdown,
}

impl DiffFormat {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            _ => Err("unsupported diff format; expected json or markdown".to_string()),
        }
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, label: &str) -> Result<T, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {label} from {}: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse {label} from {}: {error}", path.display()))
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))
}
