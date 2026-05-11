use std::error::Error;
use std::fmt;
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
    let mut results = scan_files(config, registry, discovery.files);
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
        },
        files: results,
        artifacts,
        evidence,
        findings: Vec::new(),
    })
}

fn scan_files(
    config: ScanConfig,
    registry: Arc<DetectorRegistry>,
    files: Vec<PathBuf>,
) -> Vec<FileScanResult> {
    let worker_count = thread::available_parallelism().map_or(1, usize::from);
    let chunk_size = files.len().div_ceil(worker_count).max(1);

    thread::scope(|scope| {
        let mut handles = Vec::new();

        for chunk in files.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let config = config.clone();
            let registry = Arc::clone(&registry);

            handles.push(scope.spawn(move || {
                chunk
                    .into_iter()
                    .map(|path| scan_file(&config, &registry, path))
                    .collect::<Vec<_>>()
            }));
        }

        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("file scan worker panicked"))
            .collect()
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
                }],
                evidence: vec![Evidence {
                    id: evidence_id,
                    lifecycle_stage: LifecycleStage::Store,
                    location,
                    detector_id: self.id().to_string(),
                    confidence: Confidence::High,
                    excerpt: Some(SanitizedExcerpt(input.source.to_string())),
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
}
