use sessionscope_model::{ScanReport, SkippedReason};

pub fn render(report: &ScanReport) -> String {
    let mut output = format!(
        concat!(
            "# SessionScope Report\n\n",
            "- Files discovered: {}\n",
            "- Files scanned: {}\n",
            "- Files skipped: {}\n",
            "- Findings: {}\n"
        ),
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.findings.len()
    );

    let skipped_files = report
        .files
        .iter()
        .filter_map(|file| {
            file.skipped_reason
                .as_ref()
                .map(|reason| (&file.path, reason))
        })
        .collect::<Vec<_>>();

    if !skipped_files.is_empty() {
        output.push_str("\n## Skipped Files\n\n");
        for (path, reason) in skipped_files {
            output.push_str(&format!("- `{path}`: {}\n", format_skipped_reason(reason)));
        }
    }

    output
}

fn format_skipped_reason(reason: &SkippedReason) -> &'static str {
    match reason {
        SkippedReason::Binary => "binary",
        SkippedReason::TooLarge => "too_large",
        SkippedReason::Unsupported => "unsupported",
        SkippedReason::Excluded => "excluded",
        SkippedReason::Ignored => "ignored",
        SkippedReason::SensitivePath => "sensitive_path",
        SkippedReason::ReadError(_) => "read_error",
    }
}
