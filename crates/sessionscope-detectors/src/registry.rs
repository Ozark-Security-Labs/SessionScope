use std::time::Instant;

use crate::bearer::BearerTokenDetector;
use crate::client_storage::ClientStorageDetector;
use crate::cookies::CookieSetDetector;
use crate::jwt::JwtDetector;
use crate::oauth_flow::OAuthFlowDetector;
use crate::query_params::QueryParameterTokenDetector;
use crate::reset_tokens::ResetTokenDetector;
use crate::sessions::{RefreshTokenLifecycleDetector, SessionLifecycleDetector};
use crate::{DetectionOutput, Detector, DetectorInput};

#[derive(Default)]
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn builtin() -> Self {
        Self::empty()
            .with_detector(Box::new(CookieSetDetector))
            .with_detector(Box::new(JwtDetector))
            .with_detector(Box::new(OAuthFlowDetector))
            .with_detector(Box::new(ClientStorageDetector))
            .with_detector(Box::new(BearerTokenDetector))
            .with_detector(Box::new(QueryParameterTokenDetector))
            .with_detector(Box::new(ResetTokenDetector))
            .with_detector(Box::new(SessionLifecycleDetector))
            .with_detector(Box::new(RefreshTokenLifecycleDetector))
    }

    pub fn with_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    pub fn run(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        let mut output = DetectionOutput::default();

        for detector in &self.detectors {
            let mut detector_output = detector.detect(input);
            output.artifacts.append(&mut detector_output.artifacts);
            output.evidence.append(&mut detector_output.evidence);
            output.diagnostics.append(&mut detector_output.diagnostics);
        }

        output
    }

    /// Run detectors with a wall-clock deadline. After each detector, the
    /// elapsed time since `started_at` is compared against `budget`. When the
    /// budget is exceeded, the remaining detectors are skipped and the
    /// outcome is reported via `RunOutcome::TimedOut` so the pipeline can
    /// surface a `SkippedReason::Timeout`. See F-10.
    pub fn run_with_deadline(
        &self,
        input: &DetectorInput<'_>,
        started_at: Instant,
        budget: std::time::Duration,
    ) -> RunOutcome {
        let mut output = DetectionOutput::default();

        for detector in &self.detectors {
            if started_at.elapsed() > budget {
                return RunOutcome::TimedOut;
            }
            let mut detector_output = detector.detect(input);
            if started_at.elapsed() > budget {
                return RunOutcome::TimedOut;
            }
            output.artifacts.append(&mut detector_output.artifacts);
            output.evidence.append(&mut detector_output.evidence);
            output.diagnostics.append(&mut detector_output.diagnostics);
        }

        RunOutcome::Completed(output)
    }
}

#[derive(Debug)]
pub enum RunOutcome {
    Completed(DetectionOutput),
    TimedOut,
}
