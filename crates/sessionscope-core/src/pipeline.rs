use std::error::Error;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use sessionscope_detectors::{DetectorInput, DetectorRegistry};
use sessionscope_model::{FileScanResult, SCHEMA_VERSION, ScanReport, ScanSummary, SkippedReason};

use crate::ScanConfig;
use crate::discovery::{discover_files, normalize_path};
use crate::redaction::sanitize_detection_output;
use crate::source::{classify_language, read_source};

#[derive(Debug)]
pub enum ScanError {
    Discovery(std::io::Error),
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(error) => write!(formatter, "failed to discover files: {error}"),
        }
    }
}

impl Error for ScanError {}

pub fn scan_path(
    config: ScanConfig,
    registry: Arc<DetectorRegistry>,
) -> Result<ScanReport, ScanError> {
    let discovery = discover_files(&config).map_err(ScanError::Discovery)?;
    let files_discovered = discovery.files.len() + discovery.skipped.len();
    let ScanFilesOutcome {
        mut results,
        worker_panic_count,
    } = scan_files(config, registry, discovery.files);
    results.extend(discovery.skipped);
    results.sort_by(|left, right| left.path.cmp(&right.path));

    let files_scanned = results
        .iter()
        .filter(|result| result.skipped_reason.is_none())
        .count();
    let files_skipped = results.len().saturating_sub(files_scanned);

    let mut artifacts = Vec::new();
    let mut evidence = Vec::new();
    for result in &results {
        artifacts.extend(result.artifacts.clone());
        evidence.extend(result.evidence.clone());
    }

    Ok(ScanReport {
        schema_version: SCHEMA_VERSION.to_string(),
        summary: ScanSummary {
            files_discovered,
            files_scanned,
            files_skipped,
            diagnostics: Vec::new(),
            worker_panic_count,
        },
        files: results,
        artifacts,
        evidence,
        lifecycle_paths: Vec::new(),
        findings: Vec::new(),
    })
}

struct ScanFilesOutcome {
    results: Vec<FileScanResult>,
    worker_panic_count: u32,
}

fn scan_files(
    config: ScanConfig,
    registry: Arc<DetectorRegistry>,
    files: Vec<PathBuf>,
) -> ScanFilesOutcome {
    let worker_count = thread::available_parallelism().map_or(1, usize::from);
    let chunk_size = files.len().div_ceil(worker_count).max(1);

    thread::scope(|scope| {
        let mut handles = Vec::new();

        for chunk in files.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let config = config.clone();
            let registry = Arc::clone(&registry);

            handles.push(scope.spawn(move || {
                let mut local_results = Vec::with_capacity(chunk.len());
                let mut local_panics: u32 = 0;
                for path in chunk {
                    let display_path = path
                        .strip_prefix(&config.root)
                        .map_or_else(|_| normalize_path(&path), normalize_path);
                    let language = classify_language(&path);

                    // Catch detector / per-file panics so a single misbehaving
                    // file cannot tear down the worker thread (and the scan).
                    // The panic payload is intentionally discarded — it may
                    // contain source text or secrets harvested before the
                    // panic.
                    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                        scan_file(&config, &registry, path)
                    }));
                    match outcome {
                        Ok(result) => local_results.push(result),
                        Err(_) => {
                            local_panics = local_panics.saturating_add(1);
                            local_results.push(FileScanResult::skipped(
                                display_path,
                                language,
                                SkippedReason::ReadError("detector panic".into()),
                            ));
                        }
                    }
                }
                (local_results, local_panics)
            }));
        }

        let mut results: Vec<FileScanResult> = Vec::new();
        let mut worker_panic_count: u32 = 0;
        for handle in handles {
            // A worker that itself panicked (outside our catch_unwind, e.g. an
            // allocation failure between the catch and the push) yields an
            // empty result set and contributes one panic to the counter.
            match handle.join() {
                Ok((mut worker_results, worker_panics)) => {
                    results.append(&mut worker_results);
                    worker_panic_count = worker_panic_count.saturating_add(worker_panics);
                }
                Err(_) => {
                    worker_panic_count = worker_panic_count.saturating_add(1);
                }
            }
        }

        ScanFilesOutcome {
            results,
            worker_panic_count,
        }
    })
}

fn scan_file(config: &ScanConfig, registry: &DetectorRegistry, path: PathBuf) -> FileScanResult {
    let language = classify_language(&path);
    let display_path = path
        .strip_prefix(&config.root)
        .map_or_else(|_| normalize_path(&path), normalize_path);

    if language == sessionscope_model::Language::Unknown {
        return FileScanResult::skipped(display_path, language, SkippedReason::Unsupported);
    }

    let source = match read_source(&path, config.max_file_size_bytes) {
        Ok(source) => source,
        Err(reason) => return FileScanResult::skipped(display_path, language, reason),
    };

    let detector_input = DetectorInput {
        path: &display_path,
        language,
        source: &source,
    };
    let detection = sanitize_detection_output(registry.run(&detector_input));

    let mut result = FileScanResult::scanned(display_path, language);
    result.artifacts = detection.artifacts;
    result.evidence = detection.evidence;
    result.diagnostics = detection.diagnostics;
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sessionscope_detectors::{DetectionOutput, Detector, DetectorInput, DetectorRegistry};
    use sessionscope_model::{
        Artifact, ArtifactId, ArtifactType, Confidence, Evidence, EvidenceId, LifecycleEvidence,
        LifecycleStage, SanitizedExcerpt, SourceLocation,
    };
    use tempfile::tempdir;

    use crate::{ScanConfig, scan_path};

    struct SecretEchoDetector;

    impl Detector for SecretEchoDetector {
        fn id(&self) -> &'static str {
            "test.secret_echo"
        }

        fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
            let location = SourceLocation {
                path: input.path.to_string(),
                line: Some(1),
                column: Some(1),
            };
            let evidence_id = EvidenceId("evidence_secret_echo".to_string());

            DetectionOutput {
                artifacts: vec![Artifact {
                    id: ArtifactId("artifact_secret_echo".to_string()),
                    artifact_type: ArtifactType::SessionCookie,
                    display_name: Some(
                        "session=abcdefghijklmnopqrstuvwxyzABCDEF0123456789".to_string(),
                    ),
                    locations: vec![location.clone()],
                    lifecycle_evidence: LifecycleEvidence {
                        store: vec![evidence_id.clone()],
                        ..LifecycleEvidence::default()
                    },
                    confidence: Confidence::High,
                    framework_hints: Vec::new(),
                    cookie_attributes: None,
                    jwt_attributes: None,
                    token_boundary_attributes: None,
                }],
                evidence: vec![Evidence {
                    id: evidence_id,
                    lifecycle_stage: LifecycleStage::Store,
                    location,
                    detector_id: self.id().to_string(),
                    confidence: Confidence::High,
                    excerpt: Some(SanitizedExcerpt::from_sanitized(input.source.to_string())),
                    dynamic: false,
                    framework_default: false,
                }],
                diagnostics: vec![
                    "read token abcdefghijklmnopqrstuvwxyzABCDEF0123456789".to_string(),
                ],
            }
        }
    }

    #[test]
    fn detector_output_is_sanitized_before_inventory_storage() {
        let temp = tempdir().expect("tempdir should be created");
        std::fs::write(
            temp.path().join("app.ts"),
            "const token = \"abcdefghijklmnopqrstuvwxyzABCDEF0123456789\";",
        )
        .expect("source should be written");

        let registry =
            Arc::new(DetectorRegistry::empty().with_detector(Box::new(SecretEchoDetector)));
        let report =
            scan_path(ScanConfig::new(temp.path()), registry).expect("scan should succeed");
        let serialized =
            serde_json::to_string(&report).expect("scan report should serialize to JSON");

        assert!(serialized.contains("[REDACTED]"));
        assert!(!serialized.contains("abcdefghijklmnopqrstuvwxyzABCDEF0123456789"));
        assert_eq!(report.files[0].evidence, report.evidence);
    }

    /// Detector that always panics with a payload containing fake-secret-like
    /// text. The scan pipeline must catch the panic, report the file as a
    /// `ReadError("detector panic")` skip, and never let the panic payload
    /// surface in the report (it could contain attacker-controlled source).
    struct PanickingDetector;

    impl Detector for PanickingDetector {
        fn id(&self) -> &'static str {
            "test.panic"
        }

        fn detect(&self, _input: &DetectorInput<'_>) -> DetectionOutput {
            panic!("simulated detector crash secret=PAYLOAD_DO_NOT_LEAK");
        }
    }

    #[test]
    fn worker_panics_are_caught_and_counted() {
        let temp = tempdir().expect("tempdir should be created");
        std::fs::write(temp.path().join("a.ts"), "const a = 1;").expect("source should be written");

        // Suppress the default panic hook for the duration of the scan so the
        // test output is clean. The catch_unwind in the pipeline is what
        // actually contains the panic; the hook only governs printing.
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let registry =
            Arc::new(DetectorRegistry::empty().with_detector(Box::new(PanickingDetector)));
        let report = scan_path(ScanConfig::new(temp.path()), registry)
            .expect("scan should return a report even when detectors panic");

        std::panic::set_hook(previous_hook);

        // At least one file was skipped because of the panic.
        let panicked_files: Vec<_> = report
            .files
            .iter()
            .filter(|file| {
                matches!(
                    file.skipped_reason,
                    Some(sessionscope_model::SkippedReason::ReadError(ref msg)) if msg == "detector panic"
                )
            })
            .collect();
        assert!(
            !panicked_files.is_empty(),
            "expected at least one file marked as a detector-panic skip; got files={:?}",
            report.files,
        );

        // The summary counter tracks the panic(s).
        assert!(
            report.summary.worker_panic_count >= 1,
            "expected worker_panic_count >= 1, got {}",
            report.summary.worker_panic_count,
        );

        // The panic payload must not leak into the serialized report.
        let serialized =
            serde_json::to_string(&report).expect("scan report should serialize to JSON");
        assert!(
            !serialized.contains("PAYLOAD_DO_NOT_LEAK"),
            "panic payload must not appear in the report",
        );
    }
}
