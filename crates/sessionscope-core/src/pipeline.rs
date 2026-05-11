use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use sessionscope_detectors::{DetectorInput, DetectorRegistry};
use sessionscope_model::{FileScanResult, SCHEMA_VERSION, ScanReport, ScanSummary, SkippedReason};

use crate::ScanConfig;
use crate::discovery::{discover_files, normalize_path};
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
    let files = discover_files(&config).map_err(ScanError::Discovery)?;
    let mut results = scan_files(config, registry, files.clone());
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
        schema_version: SCHEMA_VERSION,
        summary: ScanSummary {
            files_discovered: files.len(),
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

    let source = match read_source(&path, config.max_file_size_bytes) {
        Ok(source) => source,
        Err(reason) => return FileScanResult::skipped(display_path, language, reason),
    };

    if language == sessionscope_model::Language::Unknown {
        return FileScanResult::skipped(display_path, language, SkippedReason::Unsupported);
    }

    let detector_input = DetectorInput {
        path: &display_path,
        language,
        source: &source,
    };
    let detection = registry.run(&detector_input);

    let mut result = FileScanResult::scanned(display_path, language);
    result.artifacts = detection.artifacts;
    result.evidence = detection.evidence;
    result.diagnostics = detection.diagnostics;
    result
}
