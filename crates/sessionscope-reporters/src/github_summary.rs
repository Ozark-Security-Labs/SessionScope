use sessionscope_model::ScanReport;

pub fn render(report: &ScanReport) -> String {
    format!(
        concat!(
            "## SessionScope\n\n",
            "| Metric | Count |\n",
            "| --- | ---: |\n",
            "| Files discovered | {} |\n",
            "| Files scanned | {} |\n",
            "| Files skipped | {} |\n",
            "| Lifecycle paths | {} |\n",
            "| Findings | {} |\n"
        ),
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.lifecycle_paths.len(),
        report.findings.len()
    )
}
