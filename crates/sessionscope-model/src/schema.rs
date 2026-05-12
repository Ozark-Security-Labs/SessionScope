pub const SCHEMA_VERSION: &str = "0.3.0";

use crate::{ArtifactId, EvidenceId, FindingId};

/// Create a deterministic artifact ID from normalized, non-secret inputs.
///
/// Inputs should identify stable source facts such as detector ID, artifact
/// kind, normalized path, and source location. Never pass token values,
/// private keys, bearer strings, cookie values, or other runtime secrets.
pub fn stable_artifact_id(parts: &[impl AsRef<str>]) -> ArtifactId {
    ArtifactId(format!("artifact_{:016x}", stable_hash(parts)))
}

/// Create a deterministic evidence ID from normalized, non-secret inputs.
///
/// Inputs should identify stable source facts such as detector ID, lifecycle
/// stage, normalized path, source location, and a sanitized local key.
pub fn stable_evidence_id(parts: &[impl AsRef<str>]) -> EvidenceId {
    EvidenceId(format!("evidence_{:016x}", stable_hash(parts)))
}

/// Create a deterministic finding ID from normalized, non-secret inputs.
///
/// Inputs should identify stable classifier facts such as rule/category,
/// related artifact IDs, related evidence IDs, and normalized source location.
pub fn stable_finding_id(parts: &[impl AsRef<str>]) -> FindingId {
    FindingId(format!("finding_{:016x}", stable_hash(parts)))
}

fn stable_hash(parts: &[impl AsRef<str>]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET_BASIS;

    for part in parts {
        let normalized = normalize_id_part(part.as_ref());
        for byte in normalized.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

fn normalize_id_part(part: &str) -> String {
    part.trim().replace('\\', "/")
}
