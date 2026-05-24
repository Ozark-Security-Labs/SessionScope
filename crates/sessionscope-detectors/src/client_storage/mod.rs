use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, EvidenceId, Language, LifecycleEvidence,
    LifecycleStage, SanitizedExcerpt, SourceLocation, stable_artifact_id, stable_evidence_id,
};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "client.storage";
const REDACTION: &str = "[REDACTED]";

static STORAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(?:"([^"]+)"|'([^']+)')"#,
    )
    .expect("storage regex should compile")
});
static STORAGE_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)(\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(?:"(?:access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer|auth|session)[^"]*"|'(?:access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer|auth|session)[^']*')\s*,\s*)(["'`])([^"'`]*)(["'`])"#)
        .expect("storage value regex should compile")
});
static DOCUMENT_COOKIE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)document\s*\.\s*cookie\s*="#).expect("document cookie regex should compile")
});
static COOKIE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(["'`])([^="';`]+)="#).expect("cookie key regex should compile")
});
static URL_PATH_FRAGMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(#(?:access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer|session)\s*=|/(?:access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer)(?:=|/)(?:\$\{|[A-Za-z0-9._~+%-]))"#)
        .expect("url path/fragment regex should compile")
});
static CLIENT_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(client_secret|clientSecret)\b\s*[:=]\s*(["'`][^"'`]+["'`]|[A-Za-z0-9._~+/-]{12,})"#,
    )
    .expect("client secret regex should compile")
});
static SENSITIVE_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)(\b(?:access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer|auth|session|client[_-]?secret|clientSecret)\b\s*[:=,]\s*)(["'`])([^"'`]*)(["'`])"#)
        .expect("sensitive value regex should compile")
});
static CLIENT_SECRET_UNQUOTED_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(\b(?:client_secret|clientSecret)\b\s*[:=]\s*)([A-Za-z0-9._~+/-]{12,})"#)
        .expect("client secret unquoted value regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct ClientStorageDetector;

impl Detector for ClientStorageDetector {
    fn id(&self) -> &'static str {
        DETECTOR_ID
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        match input.language {
            Language::JavaScript | Language::TypeScript => detect(input),
            _ => DetectionOutput::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct Signal {
    detector_id: &'static str,
    stage: LifecycleStage,
    artifact_type: ArtifactType,
    display_name: String,
    line: usize,
    column: usize,
    confidence: Confidence,
    dynamic: bool,
    excerpt: SanitizedExcerpt,
}

fn detect(input: &DetectorInput<'_>) -> DetectionOutput {
    let mut signals = Vec::new();

    for (index, line) in input.source.lines().enumerate() {
        let line_number = index + 1;
        if let Some(captures) = STORAGE_RE.captures(line) {
            let storage = captures.get(1).map_or("", |capture| capture.as_str());
            let key = captures
                .get(2)
                .or_else(|| captures.get(3))
                .map_or("", |capture| capture.as_str());
            if is_token_shaped_name(key) && !is_allowlisted_key(key) {
                let detector_id = if storage.eq_ignore_ascii_case("localStorage") {
                    "client_storage.local_storage.set_item"
                } else {
                    "client_storage.session_storage.set_item"
                };
                signals.push(signal(
                    detector_id,
                    LifecycleStage::Store,
                    key,
                    line,
                    line_number,
                    false,
                ));
            }
        }

        if DOCUMENT_COOKIE_RE.is_match(line) {
            let key = COOKIE_KEY_RE
                .captures(line)
                .and_then(|captures| captures.get(2))
                .map_or("document_cookie", |capture| capture.as_str());
            if is_token_shaped_name(key) && !is_allowlisted_key(key) {
                signals.push(signal(
                    "client_storage.document_cookie.write",
                    LifecycleStage::Store,
                    key,
                    line,
                    line_number,
                    false,
                ));
            }
        }

        if URL_PATH_FRAGMENT_RE.is_match(line) {
            signals.push(signal(
                "client_storage.url_path_or_fragment.token",
                LifecycleStage::Transmit,
                "url_token",
                line,
                line_number,
                false,
            ));
        }

        if is_browser_client_path(input.path) && CLIENT_SECRET_RE.is_match(line) {
            signals.push(signal(
                "client_storage.browser.client_secret",
                LifecycleStage::Store,
                "client_secret",
                line,
                line_number,
                true,
            ));
        }
    }

    signals_to_output(input, signals)
}

fn signal(
    detector_id: &'static str,
    stage: LifecycleStage,
    display_name: &str,
    line: &str,
    line_number: usize,
    dynamic: bool,
) -> Signal {
    Signal {
        detector_id,
        stage,
        artifact_type: artifact_type_for_name(display_name),
        display_name: normalize_display_name(display_name),
        line: line_number,
        column: 1,
        confidence: if dynamic {
            Confidence::Medium
        } else {
            Confidence::High
        },
        dynamic,
        excerpt: SanitizedExcerpt::from_sanitized(sanitize_storage_excerpt(line)),
    }
}

fn signals_to_output(input: &DetectorInput<'_>, signals: Vec<Signal>) -> DetectionOutput {
    let mut output = DetectionOutput::default();
    for signal in signals {
        let line = signal.line.to_string();
        let column = signal.column.to_string();
        let evidence_id = stable_evidence_id(&[
            DETECTOR_ID,
            signal.detector_id,
            input.path,
            line.as_str(),
            column.as_str(),
            signal.display_name.as_str(),
        ]);
        let artifact_id = stable_artifact_id(&[
            DETECTOR_ID,
            artifact_type_part(signal.artifact_type),
            input.path,
            signal.display_name.as_str(),
        ]);
        let mut lifecycle_evidence = LifecycleEvidence::default();
        push_lifecycle_id(&mut lifecycle_evidence, signal.stage, evidence_id.clone());
        let location = SourceLocation {
            path: input.path.to_string(),
            line: Some(signal.line),
            column: Some(signal.column),
        };
        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type: signal.artifact_type,
            display_name: Some(signal.display_name),
            locations: vec![location.clone()],
            lifecycle_evidence,
            confidence: signal.confidence,
            framework_hints: vec!["browser-client".to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        });
        output.evidence.push(Evidence {
            id: evidence_id,
            lifecycle_stage: signal.stage,
            location,
            detector_id: signal.detector_id.to_string(),
            confidence: signal.confidence,
            excerpt: Some(signal.excerpt),
            dynamic: signal.dynamic,
            framework_default: false,
        });
    }
    output
}

fn is_token_shaped_name(name: &str) -> bool {
    let normalized = normalize_display_name(name);
    [
        "access_token",
        "id_token",
        "refresh_token",
        "jwt",
        "bearer",
        "auth",
        "session",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn is_allowlisted_key(name: &str) -> bool {
    matches!(
        normalize_display_name(name).as_str(),
        "theme" | "dark" | "authorship" | "session_replay_consent" | "session_storage_test"
    )
}

fn normalize_display_name(name: &str) -> String {
    name.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .replace('-', "_")
        .to_ascii_lowercase()
}

fn artifact_type_for_name(name: &str) -> ArtifactType {
    let normalized = normalize_display_name(name);
    if normalized.contains("access_token")
        || normalized.contains("id_token")
        || normalized.contains("jwt")
    {
        ArtifactType::AccessJwt
    } else if normalized.contains("refresh_token") {
        ArtifactType::RefreshJwt
    } else if normalized.contains("client_secret") {
        ArtifactType::ServiceToken
    } else if normalized.contains("session") {
        ArtifactType::OpaqueBearerToken
    } else {
        ArtifactType::UnknownToken
    }
}

fn is_browser_client_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.contains("/pages/")
        || normalized.contains("/app/")
        || normalized.contains("/src/components/")
        || normalized.contains("/components/")
        || normalized.contains("/public/")
        || normalized.starts_with("pages/")
        || normalized.starts_with("app/")
        || normalized.starts_with("src/components/")
        || normalized.starts_with("public/")
}

fn sanitize_storage_excerpt(line: &str) -> String {
    let mut output = STORAGE_VALUE_RE
        .replace_all(line, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = SENSITIVE_VALUE_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    CLIENT_SECRET_UNQUOTED_VALUE_RE
        .replace_all(&output, format!("$1{REDACTION}"))
        .to_string()
}

fn push_lifecycle_id(lifecycle: &mut LifecycleEvidence, stage: LifecycleStage, id: EvidenceId) {
    let bucket = match stage {
        LifecycleStage::Issue => &mut lifecycle.issue,
        LifecycleStage::Store => &mut lifecycle.store,
        LifecycleStage::Transmit => &mut lifecycle.transmit,
        LifecycleStage::Validate => &mut lifecycle.validate,
        LifecycleStage::Refresh => &mut lifecycle.refresh,
        LifecycleStage::Revoke => &mut lifecycle.revoke,
        LifecycleStage::Expire => &mut lifecycle.expire,
        LifecycleStage::Introspect => &mut lifecycle.introspect,
    };
    bucket.push(id);
}

fn artifact_type_part(artifact_type: ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::SessionCookie => "session_cookie",
        ArtifactType::SignedCookie => "signed_cookie",
        ArtifactType::AccessJwt => "access_jwt",
        ArtifactType::RefreshJwt => "refresh_jwt",
        ArtifactType::OpaqueBearerToken => "opaque_bearer_token",
        ArtifactType::ApiKey => "api_key",
        ArtifactType::ServiceToken => "service_token",
        ArtifactType::UnknownToken => "unknown_token",
        ArtifactType::PasswordResetToken => "password_reset_token",
        ArtifactType::EmailVerificationToken => "email_verification_token",
        ArtifactType::SessionRecord => "session_record",
        ArtifactType::OAuthAuthCodeFlow => "oauth_auth_code_flow",
        ArtifactType::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(path: &'a str, source: &'a str) -> DetectorInput<'a> {
        DetectorInput {
            path,
            source,
            language: Language::TypeScript,
        }
    }

    #[test]
    fn detects_browser_storage_and_url_token_evidence() {
        let output = ClientStorageDetector.detect(&input(
            "src/components/Auth.tsx",
            r#"
localStorage.setItem('access_token', token)
sessionStorage.setItem('refresh_token', refresh)
document.cookie = "session=" + sessionId
document.cookie = `access_token=${accessToken}`
const url = `/callback#id_token=${idToken}`
const clientSecret = 'PLACEHOLDER_SECRET_DO_NOT_USE'
"#,
        ));

        for detector_id in [
            "client_storage.local_storage.set_item",
            "client_storage.session_storage.set_item",
            "client_storage.document_cookie.write",
            "client_storage.url_path_or_fragment.token",
            "client_storage.browser.client_secret",
        ] {
            assert!(
                output
                    .evidence
                    .iter()
                    .any(|evidence| evidence.detector_id == detector_id),
                "missing {detector_id}"
            );
        }
    }

    #[test]
    fn ignores_benign_local_storage_key() {
        let output = ClientStorageDetector.detect(&input(
            "src/components/Theme.tsx",
            "localStorage.setItem('theme', 'dark')",
        ));

        assert!(output.evidence.is_empty());
    }

    #[test]
    fn redacts_storage_second_argument_literals() {
        let output = ClientStorageDetector.detect(&input(
            "src/components/Auth.tsx",
            "localStorage.setItem('access_token', `raw-token-value`)",
        ));

        let rendered = format!("{:?}", output.evidence);
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("raw-token-value"));
    }

    #[test]
    fn ignores_benign_routes_with_token_shaped_words() {
        let output = ClientStorageDetector.detect(&input(
            "src/routes.ts",
            r#"
router.get("/session", handler)
router.get("/session/callback", handler)
router.get("/auth/callback", handler)
const route = "/bearer"
"#,
        ));

        assert!(
            output
                .evidence
                .iter()
                .all(|evidence| evidence.detector_id != "client_storage.url_path_or_fragment.token"),
            "benign routes should not produce URL token evidence: {:?}",
            output.evidence
        );
    }

    #[test]
    fn keeps_explicit_url_fragment_and_path_token_evidence() {
        let output = ClientStorageDetector.detect(&input(
            "src/components/Auth.tsx",
            r#"
const fragmentUrl = `/callback#access_token=${accessToken}`
const pathUrl = `/access_token/${accessToken}`
"#,
        ));

        let count = output
            .evidence
            .iter()
            .filter(|evidence| evidence.detector_id == "client_storage.url_path_or_fragment.token")
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn only_flags_client_secret_on_browser_paths() {
        let server = ClientStorageDetector.detect(&input(
            "src/server/oauth.ts",
            "const clientSecret = 'PLACEHOLDER_SECRET_DO_NOT_USE'",
        ));
        let browser = ClientStorageDetector.detect(&input(
            "src/components/oauth.tsx",
            "const clientSecret = 'PLACEHOLDER_SECRET_DO_NOT_USE'",
        ));

        assert!(server.evidence.is_empty());
        assert!(
            browser
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "client_storage.browser.client_secret")
        );
    }

    #[test]
    fn redacts_unquoted_client_secret_literals() {
        let output = ClientStorageDetector.detect(&input(
            "src/components/Auth.tsx",
            "const clientSecret = abcdefghijklmno",
        ));

        let rendered = format!("{:?}", output.evidence);
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("abcdefghijklmno"));
    }
}
