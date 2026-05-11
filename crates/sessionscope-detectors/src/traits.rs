use sessionscope_model::{Artifact, Evidence, Language};

#[derive(Debug, Clone)]
pub struct DetectorInput<'a> {
    pub path: &'a str,
    pub language: Language,
    pub source: &'a str,
}

#[derive(Debug, Clone, Default)]
pub struct DetectionOutput {
    pub artifacts: Vec<Artifact>,
    pub evidence: Vec<Evidence>,
    pub diagnostics: Vec<String>,
}

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput;
}
