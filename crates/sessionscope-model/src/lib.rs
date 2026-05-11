pub mod artifact;
pub mod evidence;
pub mod finding;
pub mod lifecycle;
pub mod report;
pub mod schema;

pub use artifact::{Artifact, ArtifactId, ArtifactType};
pub use evidence::{Confidence, Evidence, EvidenceId, SourceLocation};
pub use finding::{Finding, FindingCategory, FindingId, Severity};
pub use lifecycle::LifecycleStage;
pub use report::{FileScanResult, Language, ScanReport, ScanSummary, SkippedReason};
pub use schema::SCHEMA_VERSION;
