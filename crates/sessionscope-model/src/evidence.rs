use crate::LifecycleStage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    /// Return the stable snake_case wire name matching the serde
    /// representation. See `FindingCategory::stable_name` for the
    /// motivation (F-07).
    pub fn stable_name(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

/// Sanitized source context suitable for reports and persisted inventory.
///
/// Values must be redacted before construction and must not contain token
/// values, private keys, bearer strings, cookie values, or runtime secrets.
///
/// The inner string is intentionally private and the type does not implement
/// `From<String>` or `From<&str>` so that callers cannot bypass the redaction
/// boundary by accident. Construct values exclusively through
/// [`sessionscope_core::redaction::sanitize_excerpt`] (or one of the other
/// `safe_excerpt*` helpers) — those run the redaction passes and truncation
/// before calling [`SanitizedExcerpt::from_sanitized`]. Detector and
/// classifier tests that need to build pre-redacted fixtures may also call
/// `from_sanitized` directly, but the name documents the contract: the
/// caller asserts the value is already sanitized.
///
/// The tuple-struct constructor is no longer reachable from outside the
/// model crate:
///
/// ```compile_fail
/// use sessionscope_model::SanitizedExcerpt;
/// // The inner field is private, so the tuple constructor cannot be used.
/// let _ = SanitizedExcerpt("oops".to_string());
/// ```
///
/// And there are no implicit conversions:
///
/// ```compile_fail
/// use sessionscope_model::SanitizedExcerpt;
/// // `From<String>` is intentionally not implemented.
/// let _: SanitizedExcerpt = "oops".to_string().into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SanitizedExcerpt {
    inner: String,
}

impl SanitizedExcerpt {
    /// Wrap a string the caller has already redacted and truncated.
    ///
    /// Prefer `sessionscope_core::redaction::sanitize_excerpt` instead;
    /// that helper enforces the redaction and truncation invariants. Tests
    /// and fixtures that legitimately know the input is already safe may
    /// call this constructor directly.
    pub fn from_sanitized(value: String) -> Self {
        Self { inner: value }
    }

    /// Borrow the sanitized text.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Consume the wrapper and return the sanitized text.
    pub fn into_inner(self) -> String {
        self.inner
    }

    /// Returns `true` when the sanitized text is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Replace the wrapped text with another already-sanitized string.
    ///
    /// Used by the redaction pipeline when re-sanitizing values that pass
    /// through `sanitize_evidence`. As with `from_sanitized`, the caller
    /// asserts the new value has already been redacted.
    pub fn replace_with_sanitized(&mut self, value: String) {
        self.inner = value;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub lifecycle_stage: LifecycleStage,
    pub location: SourceLocation,
    pub detector_id: String,
    pub confidence: Confidence,
    pub excerpt: Option<SanitizedExcerpt>,
    pub dynamic: bool,
    pub framework_default: bool,
}
