pub mod bearer;
pub mod cookies;
pub mod frameworks;
pub mod jwt;
pub mod query_params;
pub mod registry;
pub mod reset_tokens;
pub mod sessions;
pub mod traits;

pub use registry::DetectorRegistry;
pub use traits::{DetectionOutput, Detector, DetectorInput};
