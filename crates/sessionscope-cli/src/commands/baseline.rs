use crate::commands::CommandResult;
use sessionscope_core::create_baseline;
use sessionscope_model::ScanReport;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> CommandResult {
    match args.first().map(String::as_str) {
        Some("create") => create(&args[1..]),
        _ => Err("usage: sessionscope baseline create".into()),
    }
}

fn create(args: &[String]) -> CommandResult {
    let mut from = None;
    let mut output = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--from" => {
                index += 1;
                from = Some(PathBuf::from(required_value(args, index, "--from")?));
            }
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(required_value(args, index, "--output")?));
            }
            _ => {
                return Err(
                    "usage: sessionscope baseline create --from REPORT.json [--output BASELINE.json]"
                        .into(),
                );
            }
        }

        index += 1;
    }

    let from = from.ok_or("missing --from REPORT.json")?;
    let report: ScanReport = read_json(&from, "scan report")?;
    let baseline = create_baseline(
        &report,
        format!("sessionscope {}", env!("CARGO_PKG_VERSION")),
    );
    let rendered =
        serde_json::to_string_pretty(&baseline).expect("Baseline serialization should not fail");

    if let Some(output) = output {
        fs::write(&output, rendered).map_err(|error| {
            format!(
                "failed to write baseline output to {}: {error}",
                output.display()
            )
        })?;
    } else {
        println!("{rendered}");
    }

    Ok(())
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
