pub mod bearer;
pub mod client_storage;
pub mod cookies;
pub mod frameworks;
pub mod jwt;
pub mod oauth_flow;
pub mod providers;
pub mod query_params;
pub mod registry;
pub mod reset_tokens;
pub mod sessions;
pub mod traits;

pub use registry::{DetectorRegistry, RunOutcome};
pub use traits::{DetectionOutput, Detector, DetectorInput};
