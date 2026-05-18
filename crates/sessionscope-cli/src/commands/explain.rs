use crate::commands::CommandResult;
use sessionscope_model::ScanReport;
use sessionscope_reporters::render_explain;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> CommandResult {
    let finding_id = args
        .first()
        .ok_or("missing FINDING_ID for explain command")?
        .as_str();
    let mut report = None;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--report" => {
                index += 1;
                report = Some(PathBuf::from(required_value(args, index, "--report")?));
            }
            _ => {
                return Err("usage: sessionscope explain FINDING_ID --report REPORT.json".into());
            }
        }

        index += 1;
    }

    let report_path = report.ok_or("missing --report REPORT.json")?;
    let report: ScanReport = read_json(&report_path, "scan report")?;
    let rendered = render_explain(&report, finding_id).ok_or("finding not found in report")?;
    print!("{rendered}");
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
