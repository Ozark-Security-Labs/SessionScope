//! Shared helpers for loading project policy from `sessionscope.toml`.
//!
//! Both `scan` and `evaluate` honour the same configuration precedence rules:
//! CLI flags override values from `sessionscope.toml`, which override built-in
//! defaults. Without this shared module `evaluate` silently ignored the
//! project config — see finding F-12.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::enforcement::{
    EnforcementOptions, PolicyMode as EnforcementMode, parse_category, parse_severity,
};
use crate::project_config::{PolicyMode as ConfigPolicyMode, ProjectConfig};

/// CLI overrides for enforcement options. Each field is `Option`/`Vec` so
/// callers can leave values unset and inherit from the project config.
#[derive(Debug, Default)]
pub struct EnforcementOverrides {
    pub mode: Option<EnforcementMode>,
    pub fail_severity: Option<sessionscope_model::Severity>,
    pub fail_categories: Vec<sessionscope_model::FindingCategory>,
    pub include_finding_ids: Vec<String>,
    pub exclude_finding_ids: Vec<String>,
    pub baseline: Option<PathBuf>,
    /// When false, the project-config enforcement values are skipped entirely.
    /// Used by the GitHub Action wrapper which must not let checked-in TOML
    /// override action inputs during PR CI.
    pub use_policy_config: bool,
}

/// Load `sessionscope.toml` if policy config is enabled, otherwise use an empty config.
pub fn load_project_config(use_policy_config: bool) -> Result<ProjectConfig, String> {
    if use_policy_config {
        ProjectConfig::load_default().map_err(|error| error.to_string())
    } else {
        Ok(ProjectConfig::empty())
    }
}

/// Merge project config enforcement values and CLI overrides into a single
/// `EnforcementOptions`. CLI values always win over project-config values.
pub fn build_enforcement_options(
    project_config: &ProjectConfig,
    overrides: EnforcementOverrides,
) -> Result<EnforcementOptions, String> {
    let mut enforcement = EnforcementOptions::default();

    if overrides.use_policy_config {
        if let Some(config_mode) = project_config.mode {
            enforcement.mode = match config_mode {
                ConfigPolicyMode::Advisory => EnforcementMode::Advisory,
                ConfigPolicyMode::Enforce => EnforcementMode::Enforce,
            };
        }
        if let Some(config_fail_severity) = &project_config.fail_severity {
            enforcement.fail_severity = parse_severity(config_fail_severity)?;
        }
        if let Some(config_fail_categories) = &project_config.fail_categories
            && !config_fail_categories.is_empty()
        {
            enforcement.fail_categories = Some(
                config_fail_categories
                    .iter()
                    .map(|category| parse_category(category))
                    .collect::<Result<BTreeSet<_>, _>>()?,
            );
        }
        if let Some(config_include_ids) = &project_config.include_finding_ids {
            enforcement
                .include_finding_ids
                .extend(config_include_ids.iter().cloned());
        }
        if let Some(config_exclude_ids) = &project_config.exclude_finding_ids {
            enforcement
                .exclude_finding_ids
                .extend(config_exclude_ids.iter().cloned());
        }
        if let Some(config_baseline) = &project_config.baseline {
            enforcement.baseline = Some(PathBuf::from(config_baseline));
        }
    }

    if let Some(mode) = overrides.mode {
        enforcement.mode = mode;
    }
    if let Some(fail_severity) = overrides.fail_severity {
        enforcement.fail_severity = fail_severity;
    }
    if !overrides.fail_categories.is_empty() {
        enforcement.fail_categories = Some(overrides.fail_categories.into_iter().collect());
    }
    if !overrides.include_finding_ids.is_empty() {
        enforcement.include_finding_ids = overrides.include_finding_ids.into_iter().collect();
    }
    if !overrides.exclude_finding_ids.is_empty() {
        enforcement.exclude_finding_ids = overrides.exclude_finding_ids.into_iter().collect();
    }
    if let Some(baseline) = overrides.baseline {
        enforcement.baseline = Some(baseline);
    }

    Ok(enforcement)
}
