use std::sync::LazyLock;

use regex::Regex;
use sessionscope_detectors::DetectionOutput;
use sessionscope_model::{
    Artifact, Evidence, FileScanResult, Finding, SanitizedExcerpt, ScanReport, SkippedReason,
    SourceLocation,
};

pub const REDACTION: &str = "[REDACTED]";
pub const DEFAULT_MAX_EXCERPT_CHARS: usize = 400;
pub const DEFAULT_CONTEXT_LINES: usize = 1;

static PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .expect("private key regex should compile")
});
static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(authorization\s*:\s*bearer\s+)([A-Za-z0-9._~+/=-]{8,})")
        .expect("bearer regex should compile")
});
static URL_PARAM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)([?&](?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|apikey|secret|session|jwt|code)=)([^&#\s"']+)"#,
    )
    .expect("URL param regex should compile")
});
static COOKIE_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(\b(?:[A-Za-z_][A-Za-z0-9_]*|cookies\(\))\s*\.\s*(?:cookie|set_cookie|set)\s*\(\s*["'][^"']+["']\s*,\s*)(["'])([^"']*)(["'])"#,
    )
    .expect("cookie call regex should compile")
});
static SENSITIVE_QUOTED_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(["']?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|reset[_-]?token|session[_-]?token|csrf[_-]?token|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|jwt|sessionid|private[_-]?key|signing[_-]?key)\b["']?\s*[:=]\s*)(["'])([^"']*)(["'])"#,
    )
    .expect("sensitive quoted assignment regex should compile")
});
static SENSITIVE_UNQUOTED_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|reset[_-]?token|session[_-]?token|csrf[_-]?token|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|jwt|sessionid|private[_-]?key|signing[_-]?key)\b\s*[:=]\s*)([^\s,;)\]\[}'"]+)"#,
    )
    .expect("sensitive unquoted assignment regex should compile")
});
static SENSITIVE_CLAIM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(["'](?:sub|email|name|phone|address|sid|jti)["']\s*:\s*["'])([^"']+)(["'])"#,
    )
    .expect("sensitive claim regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT)[A-Z0-9_]*\b")
        .expect("placeholder secret regex should compile")
});
static LONG_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_+/=-]{32,}\b").expect("long token regex should compile")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExcerptOptions {
    pub max_chars: usize,
    pub context_lines: usize,
}

impl Default for ExcerptOptions {
    fn default() -> Self {
        Self {
            max_chars: DEFAULT_MAX_EXCERPT_CHARS,
            context_lines: DEFAULT_CONTEXT_LINES,
        }
    }
}

pub fn safe_excerpt(source: &str, max_chars: usize) -> SanitizedExcerpt {
    SanitizedExcerpt(truncate_chars(&redact_sensitive_values(source), max_chars))
}

pub fn safe_excerpt_at_location(source: &str, location: &SourceLocation) -> SanitizedExcerpt {
    safe_excerpt_at_location_with_options(source, location, ExcerptOptions::default())
}

pub fn safe_excerpt_at_location_with_options(
    source: &str,
    location: &SourceLocation,
    options: ExcerptOptions,
) -> SanitizedExcerpt {
    let excerpt = if let Some(line_number) = location.line {
        line_context(source, line_number, options.context_lines)
    } else {
        source.to_string()
    };

    safe_excerpt(&excerpt, options.max_chars)
}

pub fn redact_sensitive_values(input: &str) -> String {
    let mut output = PRIVATE_KEY_RE.replace_all(input, REDACTION).to_string();
    output = redact_cookie_headers(&output);
    output = BEARER_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output = URL_PARAM_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output = COOKIE_CALL_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = SENSITIVE_QUOTED_ASSIGNMENT_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = SENSITIVE_UNQUOTED_ASSIGNMENT_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output = SENSITIVE_CLAIM_RE
        .replace_all(&output, format!("${{1}}{REDACTION}${{3}}"))
        .to_string();
    output = JWT_RE.replace_all(&output, REDACTION).to_string();
    output = PLACEHOLDER_SECRET_RE
        .replace_all(&output, REDACTION)
        .to_string();
    LONG_TOKEN_RE
        .replace_all(&output, |captures: &regex::Captures<'_>| {
            let value = captures.get(0).expect("full capture should exist").as_str();
            if looks_high_entropy(value) {
                REDACTION.to_string()
            } else {
                value.to_string()
            }
        })
        .to_string()
}

pub fn sanitize_detection_output(mut output: DetectionOutput) -> DetectionOutput {
    for artifact in &mut output.artifacts {
        sanitize_artifact(artifact);
    }
    for evidence in &mut output.evidence {
        sanitize_evidence(evidence);
    }
    sanitize_strings(&mut output.diagnostics);
    output
}

pub fn sanitized_report(report: &ScanReport) -> ScanReport {
    let mut sanitized = report.clone();
    sanitize_report(&mut sanitized);
    sanitized
}

pub fn sanitize_report(report: &mut ScanReport) {
    sanitize_strings(&mut report.summary.diagnostics);
    for file in &mut report.files {
        sanitize_file_scan_result(file);
    }
    for artifact in &mut report.artifacts {
        sanitize_artifact(artifact);
    }
    for evidence in &mut report.evidence {
        sanitize_evidence(evidence);
    }
    for finding in &mut report.findings {
        sanitize_finding(finding);
    }
}

fn sanitize_file_scan_result(result: &mut FileScanResult) {
    sanitize_strings(&mut result.diagnostics);
    if let Some(SkippedReason::ReadError(error)) = &mut result.skipped_reason {
        *error = redact_sensitive_values(error);
    }
    for artifact in &mut result.artifacts {
        sanitize_artifact(artifact);
    }
    for evidence in &mut result.evidence {
        sanitize_evidence(evidence);
    }
}

fn sanitize_artifact(artifact: &mut Artifact) {
    if let Some(display_name) = &mut artifact.display_name {
        *display_name = redact_sensitive_values(display_name);
    }
    sanitize_strings(&mut artifact.framework_hints);
    if let Some(attributes) = &mut artifact.cookie_attributes {
        for observation in [
            &mut attributes.http_only,
            &mut attributes.secure,
            &mut attributes.same_site,
            &mut attributes.max_age,
            &mut attributes.expires,
            &mut attributes.path,
            &mut attributes.domain,
        ] {
            if let Some(value) = &mut observation.value {
                *value = redact_sensitive_values(value);
            }
        }
    }
}

fn sanitize_evidence(evidence: &mut Evidence) {
    if let Some(excerpt) = &mut evidence.excerpt {
        excerpt.0 = truncate_chars(
            &redact_sensitive_values(&excerpt.0),
            DEFAULT_MAX_EXCERPT_CHARS,
        );
    }
}

fn sanitize_finding(finding: &mut Finding) {
    finding.title = redact_sensitive_values(&finding.title);
    finding.description = redact_sensitive_values(&finding.description);
    if let Some(suggested_fix) = &mut finding.suggested_fix {
        *suggested_fix = redact_sensitive_values(suggested_fix);
    }
    if let Some(reviewer_question) = &mut finding.reviewer_question {
        *reviewer_question = redact_sensitive_values(reviewer_question);
    }
}

fn sanitize_strings(values: &mut [String]) {
    for value in values {
        *value = redact_sensitive_values(value);
    }
}

fn line_context(source: &str, line_number: usize, context_lines: usize) -> String {
    let lines = source.lines().collect::<Vec<_>>();
    if line_number == 0 || lines.is_empty() {
        return String::new();
    }

    let target = line_number.saturating_sub(1);
    let start = target.saturating_sub(context_lines);
    let end = (target + context_lines + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn redact_cookie_headers(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.contains("set-cookie:")
                || lower.contains("cookie:")
                || lower.contains("document.cookie")
            {
                redact_cookie_line(line)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_cookie_line(line: &str) -> String {
    line.split(';')
        .map(redact_cookie_segment)
        .collect::<Vec<_>>()
        .join(";")
}

fn redact_cookie_segment(segment: &str) -> String {
    let Some(equal_index) = segment.find('=') else {
        return segment.to_string();
    };
    let (left, right) = segment.split_at(equal_index + 1);
    let cookie_name = left
        .rsplit_once(|ch: char| ch == ':' || ch.is_ascii_whitespace())
        .map_or(left.trim_end_matches('='), |(_, name)| {
            name.trim_end_matches('=')
        });

    if is_safe_cookie_attribute(cookie_name) {
        segment.to_string()
    } else {
        let quote = right
            .chars()
            .next()
            .filter(|ch| *ch == '"' || *ch == '\'')
            .map_or("", |ch| if ch == '"' { "\"" } else { "'" });
        format!("{left}{quote}{REDACTION}{quote}")
    }
}

fn is_safe_cookie_attribute(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "domain" | "expires" | "max-age" | "path" | "samesite"
    )
}

fn looks_high_entropy(value: &str) -> bool {
    let trimmed = value.trim_matches(|ch: char| {
        !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' && ch != '+' && ch != '/' && ch != '='
    });
    if trimmed.len() < 32 {
        return false;
    }

    let has_alpha = trimmed.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = trimmed.chars().any(|ch| ch.is_ascii_digit());
    let has_mixed_case = trimmed.chars().any(|ch| ch.is_ascii_lowercase())
        && trimmed.chars().any(|ch| ch.is_ascii_uppercase());
    let has_token_symbol = trimmed
        .chars()
        .any(|ch| matches!(ch, '_' | '-' | '+' | '/' | '='));
    let unique_count = trimmed
        .chars()
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    has_alpha && (has_digit || has_token_symbol || has_mixed_case) && unique_count >= 12
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use sessionscope_detectors::DetectionOutput;
    use sessionscope_model::{
        Artifact, ArtifactId, ArtifactType, Confidence, CookieAttributeObservation,
        CookieAttributeState, CookieAttributes, LifecycleEvidence, SourceLocation,
    };

    use super::{
        ExcerptOptions, redact_sensitive_values, safe_excerpt_at_location_with_options,
        sanitize_detection_output,
    };

    #[test]
    fn redacts_jwt_like_values() {
        let output =
            redact_sensitive_values("Authorization: Bearer aaa.bbb.cccccccccccccccccccccc");

        assert!(output.contains("Authorization: Bearer [REDACTED]"));
        assert!(!output.contains("aaa.bbb.cccccccccccccccccccccc"));
    }

    #[test]
    fn redacts_cookie_values_but_keeps_attributes() {
        let output = redact_sensitive_values(
            "Set-Cookie: session=secret-session-value; HttpOnly; Secure; SameSite=Lax",
        );

        assert!(output.contains("session=[REDACTED]"));
        assert!(output.contains("HttpOnly"));
        assert!(output.contains("Secure"));
        assert!(output.contains("SameSite=Lax"));
        assert!(!output.contains("secret-session-value"));
    }

    #[test]
    fn redacts_private_keys() {
        let output = redact_sensitive_values(
            "key = -----BEGIN PRIVATE KEY-----\nabc123SECRET\n-----END PRIVATE KEY-----",
        );

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("abc123SECRET"));
    }

    #[test]
    fn redacts_sensitive_assignments_url_params_and_claim_values() {
        let output = redact_sensitive_values(
            "client_secret=\"abcd1234SECRET\" /callback?access_token=abcd1234SECRET {\"sub\":\"user-123\", \"aud\":\"api\"}",
        );

        assert!(output.contains("client_secret=\"[REDACTED]\""));
        assert!(output.contains("access_token=[REDACTED]"));
        assert!(output.contains("\"sub\":\"[REDACTED]\""));
        assert!(output.contains("\"aud\":\"api\""));
        assert!(!output.contains("abcd1234SECRET"));
        assert!(!output.contains("user-123"));
    }

    #[test]
    fn redacts_full_quoted_sensitive_assignments_with_punctuation() {
        let output = redact_sensitive_values(
            "\"client_secret\": \"prod-secret:tenant@example.com with spaces\"; api_key='key$with:symbols@example.com'",
        );

        assert!(output.contains("\"client_secret\": \"[REDACTED]\""));
        assert!(output.contains("api_key='[REDACTED]'"));
        assert!(!output.contains("prod-secret"));
        assert!(!output.contains("tenant@example.com"));
        assert!(!output.contains("key$with"));
    }

    #[test]
    fn redacts_framework_cookie_call_values() {
        for source in [
            "res.cookie(\"session\", \"short-secret\", { httpOnly: true, secure: true })",
            "response.set_cookie(\"session\", \"short-secret\", httponly=True)",
            "cookies().set(\"access\", \"short-secret\", { sameSite: \"lax\" })",
        ] {
            let output = redact_sensitive_values(source);

            assert!(output.contains("[REDACTED]"), "{source} was not redacted");
            assert!(!output.contains("short-secret"));
            assert!(output.contains("session") || output.contains("access"));
            assert!(
                output.contains("httpOnly")
                    || output.contains("httponly")
                    || output.contains("sameSite")
            );
        }
    }

    #[test]
    fn redacts_high_entropy_token_like_values() {
        let output = redact_sensitive_values("token abcdefghijklmnopqrstuvwxyzABCDEF0123456789");

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("abcdefghijklmnopqrstuvwxyzABCDEF0123456789"));
    }

    #[test]
    fn redacts_placeholder_secret_values() {
        let output = redact_sensitive_values(
            "const rotatedRefreshToken = \"PLACEHOLDER_RESET_TOKEN_ROTATED\"; const signingSecret = \"PLACEHOLDER_SECRET_DO_NOT_USE\";",
        );

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("PLACEHOLDER_RESET_TOKEN_ROTATED"));
        assert!(!output.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    }

    #[test]
    fn safe_excerpt_uses_line_context_and_max_length() {
        let source = concat!(
            "const safe = true;\n",
            "const token = \"abcdefghijklmnopqrstuvwxyzABCDEF0123456789\";\n",
            "const secure = true;\n",
        );
        let location = SourceLocation {
            path: "src/auth.ts".to_string(),
            line: Some(2),
            column: Some(7),
        };

        let excerpt = safe_excerpt_at_location_with_options(
            source,
            &location,
            ExcerptOptions {
                max_chars: 80,
                context_lines: 1,
            },
        );

        assert!(excerpt.0.contains("const safe"));
        assert!(excerpt.0.contains("const secure"));
        assert!(excerpt.0.contains("[REDACTED]"));
        assert!(excerpt.0.chars().count() <= 80);
        assert!(
            !excerpt
                .0
                .contains("abcdefghijklmnopqrstuvwxyzABCDEF0123456789")
        );
    }

    #[test]
    fn sanitizes_cookie_attribute_values() {
        let secret = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789";
        let output = sanitize_detection_output(DetectionOutput {
            artifacts: vec![Artifact {
                id: ArtifactId("artifact_cookie".to_string()),
                artifact_type: ArtifactType::SessionCookie,
                display_name: Some("session".to_string()),
                locations: Vec::new(),
                lifecycle_evidence: LifecycleEvidence::default(),
                confidence: Confidence::High,
                framework_hints: Vec::new(),
                cookie_attributes: Some(cookie_attributes_with_value(secret)),
            }],
            evidence: Vec::new(),
            diagnostics: Vec::new(),
        });

        let value = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("attributes should remain")
            .domain
            .value
            .as_deref()
            .expect("value should remain");
        assert_eq!(value, "[REDACTED]");
    }

    fn cookie_attributes_with_value(value: &str) -> CookieAttributes {
        let missing = CookieAttributeObservation {
            state: CookieAttributeState::Missing,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        CookieAttributes {
            http_only: missing.clone(),
            secure: missing.clone(),
            same_site: missing.clone(),
            max_age: missing.clone(),
            expires: missing.clone(),
            path: missing.clone(),
            domain: CookieAttributeObservation {
                state: CookieAttributeState::Present,
                value: Some(value.to_string()),
                evidence_ids: Vec::new(),
                confidence: Confidence::High,
            },
        }
    }
}
