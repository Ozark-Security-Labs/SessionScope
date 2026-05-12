use crate::cookies::CookieSetDetector;
use crate::jwt::JwtDetector;
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
}
