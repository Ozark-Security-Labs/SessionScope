use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, EvidenceId, Language, LifecycleEvidence,
    LifecycleStage, SanitizedExcerpt, SourceLocation, stable_artifact_id, stable_evidence_id,
};

use crate::{DetectionOutput, Detector, DetectorInput};

pub struct ResetTokenDetector;

impl Detector for ResetTokenDetector {
    fn id(&self) -> &'static str {
        "reset.lifecycle"
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        if !matches!(
            input.language,
            Language::JavaScript | Language::TypeScript | Language::Python
        ) {
            return DetectionOutput::default();
        }

        let mut families = Vec::new();
        if first_matching_location(input, TokenFamily::PasswordReset.issue_terms()).is_some() {
            families.push(TokenFamily::PasswordReset);
        }
        if first_matching_location(input, TokenFamily::EmailVerification.issue_terms()).is_some() {
            families.push(TokenFamily::EmailVerification);
        }
        if families.is_empty() {
            return DetectionOutput::default();
        }

        let mut output = DetectionOutput::default();
        for family in families {
            append_family_evidence(input, family, &mut output);
        }
        output
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenFamily {
    PasswordReset,
    EmailVerification,
}

impl TokenFamily {
    fn artifact_type(self) -> ArtifactType {
        match self {
            Self::PasswordReset => ArtifactType::PasswordResetToken,
            Self::EmailVerification => ArtifactType::EmailVerificationToken,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset_token",
            Self::EmailVerification => "email_verification_token",
        }
    }

    fn detector_prefix(self) -> &'static str {
        match self {
            Self::PasswordReset => "reset",
            Self::EmailVerification => "verification",
        }
    }

    fn issue_terms(self) -> &'static [&'static str] {
        match self {
            Self::PasswordReset => &[
                "create_reset_token",
                "createresettoken",
                "generate_reset",
                "generatereset",
                "password_reset_token",
                "reset_token",
                "resettoken",
            ],
            Self::EmailVerification => &[
                "create_verification_token",
                "createverificationtoken",
                "generate_verification",
                "generateverification",
                "verification_token",
                "verificationtoken",
                "email_verification_token",
                "emailverificationtoken",
            ],
        }
    }
}

fn append_family_evidence(
    input: &DetectorInput<'_>,
    family: TokenFamily,
    output: &mut DetectionOutput,
) {
    let mut lifecycle = LifecycleEvidence::default();
    let mut locations = Vec::new();

    if let Some(location) = first_matching_location(input, family.issue_terms()) {
        let evidence_id = push_evidence(
            input,
            family,
            LifecycleStage::Issue,
            "issue",
            &location,
            output,
        );
        lifecycle.issue.push(evidence_id);
        locations.push(location);
    }

    if let Some(location) = first_matching_location(
        input,
        &[
            "expires_at",
            "expires",
            "expiry",
            "ttl",
            "timedelta",
            "max_age",
            "maxage",
            "expiresat",
        ],
    ) {
        let evidence_id = push_evidence(
            input,
            family,
            LifecycleStage::Expire,
            "expire",
            &location,
            output,
        );
        lifecycle.expire.push(evidence_id);
        locations.push(location);
    }

    if let Some(location) = first_matching_location(
        input,
        &[
            "single_use",
            "singleuse",
            "used_at",
            "consumed",
            "consume",
            "delete",
            "revoke",
            "invalidate",
        ],
    ) {
        let evidence_id = push_evidence(
            input,
            family,
            LifecycleStage::Revoke,
            "single_use",
            &location,
            output,
        );
        lifecycle.revoke.push(evidence_id);
        locations.push(location);
    }

    if lifecycle.issue.is_empty() && lifecycle.expire.is_empty() && lifecycle.revoke.is_empty() {
        return;
    }

    locations.sort_by_key(|left| (left.line, left.column));
    locations.dedup();
    let artifact_id = stable_artifact_id(&[
        "reset.lifecycle",
        artifact_type_part(family.artifact_type()),
        input.path,
        family.display_name(),
    ]);

    output.artifacts.push(Artifact {
        id: artifact_id,
        artifact_type: family.artifact_type(),
        display_name: Some(family.display_name().to_string()),
        locations,
        lifecycle_evidence: lifecycle,
        confidence: Confidence::Medium,
        framework_hints: Vec::new(),
        cookie_attributes: None,
        jwt_attributes: None,
        token_boundary_attributes: None,
    });
}

fn push_evidence(
    input: &DetectorInput<'_>,
    family: TokenFamily,
    stage: LifecycleStage,
    signal: &str,
    location: &SourceLocation,
    output: &mut DetectionOutput,
) -> EvidenceId {
    let detector_id = format!("{}.{}", family.detector_prefix(), signal);
    let evidence_id = stable_evidence_id(&[
        detector_id.as_str(),
        input.path,
        &location.line.unwrap_or_default().to_string(),
        family.display_name(),
    ]);
    output.evidence.push(Evidence {
        id: evidence_id.clone(),
        lifecycle_stage: stage,
        location: location.clone(),
        detector_id,
        confidence: Confidence::Medium,
        excerpt: Some(SanitizedExcerpt::from_sanitized(format!(
            "{} {} evidence",
            family.display_name(),
            stage.stable_name()
        ))),
        dynamic: false,
        framework_default: false,
    });
    evidence_id
}

fn first_matching_location(input: &DetectorInput<'_>, terms: &[&str]) -> Option<SourceLocation> {
    input.source.lines().enumerate().find_map(|(index, line)| {
        let normalized = normalize(line);
        terms
            .iter()
            .any(|term| contains_term(&normalized, term))
            .then(|| SourceLocation {
                path: input.path.to_string(),
                line: Some(index + 1),
                column: Some(1),
            })
    })
}

fn contains_term(normalized: &str, term: &str) -> bool {
    let bytes = normalized.as_bytes();
    normalized.match_indices(term).any(|(start, matched)| {
        let before = start.checked_sub(1).map(|index| bytes[index]);
        let after = bytes.get(start + matched.len()).copied();
        !is_identifier_byte(before) && !is_identifier_byte(after)
    })
}

fn is_identifier_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|value| value.is_ascii_alphanumeric() || value == b'_')
}

fn normalize(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn artifact_type_part(artifact_type: ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::PasswordResetToken => "password_reset_token",
        ArtifactType::EmailVerificationToken => "email_verification_token",
        _ => "token",
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{ArtifactType, Language, LifecycleStage};

    use super::*;

    fn detect(language: Language, source: &str) -> DetectionOutput {
        ResetTokenDetector.detect(&DetectorInput {
            path: match language {
                Language::Python => "auth.py",
                _ => "auth.ts",
            },
            language,
            source,
        })
    }

    #[test]
    fn detects_password_reset_issue_expiry_and_single_use() {
        let output = detect(
            Language::Python,
            r#"
def create_reset_token(user_id):
    expires_at = now() + timedelta(minutes=30)
    return {"token": "PLACEHOLDER_RESET_TOKEN", "single_use": True, "expires_at": expires_at}
"#,
        );

        let artifact = output
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == ArtifactType::PasswordResetToken)
            .expect("password reset artifact should be emitted");
        assert_eq!(
            artifact.display_name.as_deref(),
            Some("password_reset_token")
        );
        assert!(!artifact.lifecycle_evidence.issue.is_empty());
        assert!(!artifact.lifecycle_evidence.expire.is_empty());
        assert!(!artifact.lifecycle_evidence.revoke.is_empty());
        assert!(output.evidence.iter().any(|evidence| {
            evidence.detector_id == "reset.expire"
                && evidence.lifecycle_stage == LifecycleStage::Expire
        }));
        let debug = format!("{:#?}", output.evidence);
        assert!(!debug.contains("PLACEHOLDER_RESET_TOKEN"));
    }

    #[test]
    fn detects_email_verification_tokens() {
        let output = detect(
            Language::TypeScript,
            r#"
export function createVerificationToken(userId: string) {
  return { verification_token: token, expiresAt, consumed: false };
}
"#,
        );

        assert!(
            output
                .artifacts
                .iter()
                .any(|artifact| artifact.artifact_type == ArtifactType::EmailVerificationToken)
        );
    }

    #[test]
    fn ignores_placeholder_reset_token_literals_without_reset_flow() {
        let output = detect(
            Language::TypeScript,
            r#"response.cookie("session", "PLACEHOLDER_RESET_TOKEN", { signed: true });"#,
        );

        assert!(output.artifacts.is_empty());
        assert!(output.evidence.is_empty());
    }
}
