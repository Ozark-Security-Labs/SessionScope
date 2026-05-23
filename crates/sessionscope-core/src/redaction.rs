use std::sync::LazyLock;

use regex::Regex;
use sessionscope_detectors::DetectionOutput;
use sessionscope_model::{
    Artifact, Evidence, FileScanResult, Finding, LifecyclePath, SanitizedExcerpt, ScanReport,
    SkippedReason, SourceLocation,
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
static API_KEY_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Authorization: Bearer values are handled by BEARER_RE; this covers API-key style headers.
    Regex::new(r#"(?ix)(["']?(?:x-api-key|x_api_key|api-key|api_key|apikey)["']?\s*[:=]\s*)(["']?)([^"',}\]\s]+)(["']?)"#)
        .expect("api key header regex should compile")
});
static URL_PARAM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)([?&#](?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|apikey|secret|session|jwt|code|state|nonce|code[_-]?verifier|code[_-]?challenge)=)([^&#\s"']+)"#,
    )
    .expect("URL param regex should compile")
});
static COOKIE_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(\b(?:[A-Za-z_][A-Za-z0-9_]*|cookies\(\))\s*\.\s*(?:cookie|set_cookie|set)\s*\(\s*["'][^"']+["']\s*,\s*)(["'])([^"']*)(["'])"#,
    )
    .expect("cookie call regex should compile")
});
static BROWSER_STORAGE_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)(\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(?:"(?:access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer|auth|session)[^"]*"|'(?:access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer|auth|session)[^']*')\s*,\s*)(["'`])([^"'`]*)(["'`])"#)
        .expect("browser storage call regex should compile")
});
static COOKIE_VALUE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)(\bvalue\s*[:=]\s*)(["'])([^"']*)(["'])"#)
        .expect("cookie value key regex should compile")
});
static JWT_API_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?sx)\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?(?:sign|verify|decode|encode|jwtVerify|decodeJwt)\s*\((?:[^()]|\([^)]*\)){0,600}\)"#,
    )
    .expect("JWT API call regex should compile")
});
static QUOTED_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
        .expect("quoted literal regex should compile")
});
static SENSITIVE_QUOTED_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(["']?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|reset[_-]?token|session[_-]?token|csrf[_-]?token|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|jwt|sessionid|private[_-]?key|signing[_-]?key|state|nonce|code[_-]?verifier|code[_-]?challenge|codeVerifier|codeChallenge)\b["']?\s*[:=]\s*)(["'])([^"']*)(["'])"#,
    )
    .expect("sensitive quoted assignment regex should compile")
});
static SENSITIVE_UNQUOTED_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|reset[_-]?token|session[_-]?token|bearer[_-]?token|service[_-]?token|authorization|csrf[_-]?token|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|jwt|sessionid|private[_-]?key|signing[_-]?key|state|nonce|code[_-]?verifier|code[_-]?challenge|codeVerifier|codeChallenge)\b\s*[:=]\s*)([^\s,;)\]\[}'"]+)"#,
    )
    .expect("sensitive unquoted assignment regex should compile")
});
static SENSITIVE_CLAIM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(["']?(?:sub|email|email_verified|emailVerified|phone|address|sid|jti|user_id|userId|uid|tenant|tenant_id|tenantId|org|org_id|organization_id|organizationId|workspace|workspace_id|workspaceId|role|roles|scope|scopes|groups|amr|acr|auth_method|authMethod|auth_class|authClass)["']?\s*:\s*["'])([^"']+)(["'])"#,
    )
    .expect("sensitive claim regex should compile")
});
static SENSITIVE_CLAIM_COLLECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(["']?(?:role|roles|scope|scopes|groups|amr|acr|auth_method|authMethod|auth_class|authClass)["']?\s*:\s*)(\[[^\]]*\]|\{[^}]*\})"#,
    )
    .expect("sensitive claim collection regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        .expect("email regex should compile")
});
static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT|KEY)[A-Z0-9_]*\b")
        .expect("placeholder secret regex should compile")
});
static LONG_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_+/=-]{32,}\b").expect("long token regex should compile")
});

/// Domain hint that detectors pass when asking the redaction layer to sanitize
/// an excerpt. When the context is anything other than `Generic` the redactor
/// also strips any string literal longer than 16 characters, regardless of the
/// surrounding variable name. This is the F-09 mitigation: a Cookies or Jwt
/// detector flagging `let magic_token = "abcDEF12345678901234"` should not
/// leak the literal just because `magic_token` is not in the sensitive-name
/// regexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionContext {
    Cookies,
    Jwt,
    Bearer,
    ApiKey,
    OAuth,
    Generic,
}

impl RedactionContext {
    fn requires_literal_stripping(self) -> bool {
        !matches!(self, Self::Generic)
    }
}

/// Minimum length of a string literal that the literal-stripping pass treats
/// as suspect. Shorter literals are left intact so excerpts remain readable
/// (e.g. short attribute keys, framework hint strings).
const LITERAL_REDACTION_MIN_LEN: usize = 16;

static LONG_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#).expect("long literal regex should compile")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExcerptOptions {
    pub max_chars: usize,
    pub context_lines: usize,
    pub context: RedactionContext,
}

impl Default for ExcerptOptions {
    fn default() -> Self {
        Self {
            max_chars: DEFAULT_MAX_EXCERPT_CHARS,
            context_lines: DEFAULT_CONTEXT_LINES,
            context: RedactionContext::Generic,
        }
    }
}

pub fn safe_excerpt(source: &str, max_chars: usize) -> SanitizedExcerpt {
    safe_excerpt_with_context(source, max_chars, RedactionContext::Generic)
}

pub fn safe_excerpt_with_context(
    source: &str,
    max_chars: usize,
    context: RedactionContext,
) -> SanitizedExcerpt {
    let mut redacted = redact_sensitive_values(source);
    if context.requires_literal_stripping() {
        redacted = strip_long_string_literals(&redacted);
    }
    SanitizedExcerpt::from_sanitized(truncate_chars(&redacted, max_chars))
}

/// Run the standard redaction + default-truncation pipeline and wrap the
/// result in [`SanitizedExcerpt`]. Equivalent to
/// `safe_excerpt(raw, DEFAULT_MAX_EXCERPT_CHARS)` but with a name that
/// matches the F-06 trust-boundary docs: every detector excerpt should
/// flow through this helper (or `safe_excerpt`/`safe_excerpt_at_location`)
/// rather than constructing `SanitizedExcerpt` directly.
pub fn sanitize_excerpt(raw: &str) -> SanitizedExcerpt {
    safe_excerpt(raw, DEFAULT_MAX_EXCERPT_CHARS)
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

    safe_excerpt_with_context(&excerpt, options.max_chars, options.context)
}

/// Replace any string literal longer than `LITERAL_REDACTION_MIN_LEN`
/// characters of payload with `[REDACTED]`. Quoting is preserved so the
/// resulting excerpt remains visually parseable.
fn strip_long_string_literals(input: &str) -> String {
    LONG_LITERAL_RE
        .replace_all(input, |captures: &regex::Captures<'_>| {
            let value = captures.get(0).expect("full capture").as_str();
            // The value still has surrounding quotes; subtract them when
            // measuring the payload length so we don't redact short labels.
            if value.len() >= LITERAL_REDACTION_MIN_LEN + 2 {
                let quote = &value[..1];
                format!("{quote}{REDACTION}{quote}")
            } else {
                value.to_string()
            }
        })
        .to_string()
}

pub fn redact_sensitive_values(input: &str) -> String {
    let mut output = PRIVATE_KEY_RE.replace_all(input, REDACTION).to_string();
    output = redact_cookie_headers(&output);
    output = redact_jwt_api_calls(&output);
    output = BEARER_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output = API_KEY_HEADER_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = URL_PARAM_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output = COOKIE_CALL_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = BROWSER_STORAGE_CALL_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = COOKIE_VALUE_KEY_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = SENSITIVE_QUOTED_ASSIGNMENT_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = SENSITIVE_UNQUOTED_ASSIGNMENT_RE
        .replace_all(&output, |captures: &regex::Captures<'_>| {
            let prefix = captures.get(1).map_or("", |capture| capture.as_str());
            let value = captures.get(2).map_or("", |capture| capture.as_str());
            if prefix.to_ascii_lowercase().contains("authorization")
                && value.eq_ignore_ascii_case("bearer")
            {
                captures
                    .get(0)
                    .expect("full capture should exist")
                    .as_str()
                    .to_string()
            } else {
                format!("{prefix}{REDACTION}")
            }
        })
        .to_string();
    output = SENSITIVE_CLAIM_RE
        .replace_all(&output, format!("${{1}}{REDACTION}${{3}}"))
        .to_string();
    output = SENSITIVE_CLAIM_COLLECTION_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output = EMAIL_RE.replace_all(&output, REDACTION).to_string();
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

fn redact_jwt_api_calls(input: &str) -> String {
    JWT_API_CALL_RE
        .replace_all(input, |captures: &regex::Captures<'_>| {
            let call = captures.get(0).expect("full capture should exist").as_str();
            QUOTED_LITERAL_RE
                .replace_all(call, |literal: &regex::Captures<'_>| {
                    let value = literal
                        .get(0)
                        .expect("literal capture should exist")
                        .as_str();
                    let quote = &value[..1];
                    format!("{quote}{REDACTION}{quote}")
                })
                .to_string()
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
    for path in &mut report.lifecycle_paths {
        sanitize_lifecycle_path(path);
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
    if let Some(attributes) = &mut artifact.jwt_attributes {
        for observation in [
            &mut attributes.operation,
            &mut attributes.algorithm,
            &mut attributes.key_reference,
            &mut attributes.issuer,
            &mut attributes.audience,
            &mut attributes.expiration,
            &mut attributes.signature_verification,
            &mut attributes.expiry_enforcement,
        ] {
            if let Some(value) = &mut observation.value {
                *value = redact_sensitive_values(value);
            }
        }
        if let Some(identity_claims) = &mut attributes.identity_claims {
            for observation in [
                &mut identity_claims.subject,
                &mut identity_claims.user_id,
                &mut identity_claims.tenant_id,
                &mut identity_claims.org_id,
                &mut identity_claims.workspace_id,
                &mut identity_claims.roles,
                &mut identity_claims.scopes,
                &mut identity_claims.groups,
                &mut identity_claims.email,
                &mut identity_claims.email_verified,
                &mut identity_claims.auth_method,
                &mut identity_claims.auth_class,
            ] {
                if let Some(value) = &mut observation.value {
                    *value = redact_sensitive_values(value);
                }
            }
        }
    }
    if let Some(attributes) = &mut artifact.token_boundary_attributes {
        for observation in [
            &mut attributes.issuer,
            &mut attributes.audience,
            &mut attributes.service,
            &mut attributes.environment,
            &mut attributes.tenant,
            &mut attributes.provider,
            &mut attributes.scope,
            &mut attributes.trust_boundary,
        ] {
            if let Some(value) = &mut observation.value {
                *value = redact_sensitive_values(value);
            }
        }
    }
}

fn sanitize_evidence(evidence: &mut Evidence) {
    if let Some(excerpt) = &mut evidence.excerpt {
        // F-22: skip the costly regex pass when the excerpt is already
        // canonical — shorter than the truncation budget AND unchanged by
        // `redact_sensitive_values`. Excerpts emitted by `safe_excerpt`
        // already meet both invariants, so a second sanitize pass (e.g.
        // `sanitize_report` after `sanitize_detection_output`) is a no-op
        // we can short-circuit.
        let current = excerpt.as_str();
        if current.chars().count() <= DEFAULT_MAX_EXCERPT_CHARS {
            let redacted = redact_sensitive_values(current);
            if redacted == current {
                return;
            }
            let sanitized = truncate_chars(&redacted, DEFAULT_MAX_EXCERPT_CHARS);
            excerpt.replace_with_sanitized(sanitized);
            return;
        }
        let sanitized =
            truncate_chars(&redact_sensitive_values(current), DEFAULT_MAX_EXCERPT_CHARS);
        excerpt.replace_with_sanitized(sanitized);
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

fn sanitize_lifecycle_path(path: &mut LifecyclePath) {
    if let Some(reviewer_question) = &mut path.reviewer_question {
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
        CookieAttributeState, CookieAttributes, JwtAttributeObservation, JwtAttributeState,
        JwtAttributes, JwtIdentityClaims, LifecycleEvidence, SourceLocation,
    };

    use super::{
        ExcerptOptions, RedactionContext, redact_sensitive_values,
        safe_excerpt_at_location_with_options, safe_excerpt_with_context,
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
    fn redacts_short_jwt_api_positional_literals() {
        let output = redact_sensitive_values(
            r#"jwt.sign({ sub: "user-123" }, "dev-secret"); jwt.verify("opaque-token", "secret"); jwt.decode("short-token"); jwt.decode(token, key="tiny", algorithms=["HS256"])"#,
        );

        for leaked in [
            "user-123",
            "dev-secret",
            "opaque-token",
            "short-token",
            "\"secret\"",
            "\"tiny\"",
            "HS256",
        ] {
            assert!(!output.contains(leaked), "{leaked} leaked in {output}");
        }
        assert!(output.contains("[REDACTED]"));
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
            "client_secret=\"abcd1234SECRET\" /callback?access_token=abcd1234SECRET {\"sub\":\"user-123\", \"aud\":\"api\", \"roles\":[\"admin\"], tenant_id:\"tenant-123\"}",
        );

        assert!(output.contains("client_secret=\"[REDACTED]\""));
        assert!(output.contains("access_token=[REDACTED]"));
        assert!(output.contains("\"sub\":\"[REDACTED]\""));
        assert!(output.contains("\"aud\":\"api\""));
        assert!(output.contains("\"roles\":[REDACTED]"));
        assert!(output.contains("tenant_id:\"[REDACTED]\""));
        assert!(!output.contains("abcd1234SECRET"));
        assert!(!output.contains("user-123"));
        assert!(!output.contains("admin"));
        assert!(!output.contains("tenant-123"));
    }

    #[test]
    fn redacts_short_unquoted_bearer_and_service_tokens() {
        let output = redact_sensitive_values(
            "bearer_token=opaqueValue service_token=opaqueValue authorization=opaqueValue",
        );

        assert!(output.contains("bearer_token=[REDACTED]"));
        assert!(output.contains("service_token=[REDACTED]"));
        assert!(output.contains("authorization=[REDACTED]"));
        assert!(!output.contains("opaqueValue"));
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
            "cookies().set({ name: \"session\", value: \"short-secret\", httpOnly: true })",
            "response.set_cookie(key=\"session\", value=\"short-secret\", httponly=True)",
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
    fn redacts_oauth_state_nonce_and_pkce_material() {
        let source = concat!(
            "const state = \"abcdefghijklmnopqrstuvwxyzABCDEF0123456789\";\n",
            "const nonce = 'ZYXWVUTSRQPONMLKJIHGFEDCBA987654';\n",
            "const code_verifier = \"verifierabcdefghijklmnopqrstuvwxyz123456\";\n",
            "const codeChallenge = 'challengeabcdefghijklmnopqrstuvwxyz123456';\n",
            "const callback = \"/cb?state=stateabcdefghijklmnopqrstuvwxyz123456&nonce=nonceabcdefghijklmnopqrstuvwxyz123456#code_challenge=challengeabcdefghijklmnopqrstuvwxyz123456\";"
        );

        let output = redact_sensitive_values(source);

        for secret in [
            "abcdefghijklmnopqrstuvwxyzABCDEF0123456789",
            "ZYXWVUTSRQPONMLKJIHGFEDCBA987654",
            "verifierabcdefghijklmnopqrstuvwxyz123456",
            "challengeabcdefghijklmnopqrstuvwxyz123456",
            "stateabcdefghijklmnopqrstuvwxyz123456",
            "nonceabcdefghijklmnopqrstuvwxyz123456",
        ] {
            assert!(!output.contains(secret), "OAuth value leaked: {output}");
        }
        assert!(output.contains("state = \"[REDACTED]\""));
        assert!(output.contains("nonce = '[REDACTED]'"));
        assert!(output.contains("code_verifier = \"[REDACTED]\""));
        assert!(output.contains("codeChallenge = '[REDACTED]'"));
        assert!(output.contains("state=[REDACTED]"));
        assert!(output.contains("nonce=[REDACTED]"));
        assert!(output.contains("code_challenge=[REDACTED]"));
    }

    #[test]
    fn redacts_browser_storage_token_values() {
        let output = redact_sensitive_values(
            "localStorage.setItem('access_token', `raw-token-value`); sessionStorage.setItem(\"refresh_token\", 'short-secret')",
        );

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("raw-token-value"));
        assert!(!output.contains("short-secret"));
    }

    #[test]
    fn redacts_placeholder_secret_values() {
        let output = redact_sensitive_values(
            "const rotatedRefreshToken = \"PLACEHOLDER_RESET_TOKEN_ROTATED\"; const signingSecret = \"PLACEHOLDER_SECRET_DO_NOT_USE\"; const apiKey = \"PLACEHOLDER_API_KEY_DO_NOT_USE\";",
        );

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("PLACEHOLDER_RESET_TOKEN_ROTATED"));
        assert!(!output.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
        assert!(!output.contains("PLACEHOLDER_API_KEY_DO_NOT_USE"));
    }

    // F-09: literals longer than the threshold must be redacted whenever a
    // detector passes a non-Generic domain hint, even if the surrounding
    // variable name does not match the sensitive-name regexes.
    #[test]
    fn context_aware_excerpt_redacts_neutrally_named_literals_in_sensitive_domains() {
        let source = r#"const magic_token = "abcDEF12345678901234";"#;

        for context in [
            RedactionContext::Cookies,
            RedactionContext::Jwt,
            RedactionContext::Bearer,
            RedactionContext::ApiKey,
            RedactionContext::OAuth,
        ] {
            let excerpt = safe_excerpt_with_context(source, 200, context);
            assert!(
                excerpt.as_str().contains("[REDACTED]"),
                "{context:?} excerpt did not redact: {}",
                excerpt.as_str()
            );
            assert!(
                !excerpt.as_str().contains("abcDEF12345678901234"),
                "{context:?} excerpt leaked literal: {}",
                excerpt.as_str()
            );
        }
    }

    #[test]
    fn generic_context_preserves_neutrally_named_short_literals() {
        // The Generic context must not strip literals that the sensitive-name
        // regexes did not match — this keeps excerpts useful for unrelated
        // detectors that are not bound to an auth domain.
        let source = r#"const magic_token = "abcDEF12345678901234";"#;
        let excerpt = safe_excerpt_with_context(source, 200, RedactionContext::Generic);

        assert!(
            excerpt.as_str().contains("abcDEF12345678901234"),
            "Generic context unexpectedly redacted literal: {}",
            excerpt.as_str()
        );
    }

    #[test]
    fn context_aware_excerpt_loads_fixture_files() {
        // Round-trip through the fixtures/redaction_secrets/ files to lock in
        // the contract: any detector pulling these files in must see the
        // literal redacted.
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures = manifest_dir
            .join("..")
            .join("..")
            .join("fixtures")
            .join("redaction_secrets");

        for (file, context) in [
            ("cookies.ts", RedactionContext::Cookies),
            ("jwt.ts", RedactionContext::Jwt),
            ("bearer.ts", RedactionContext::Bearer),
            ("apikey.ts", RedactionContext::ApiKey),
        ] {
            let source = std::fs::read_to_string(fixtures.join(file))
                .expect("fixture file should be readable");
            let excerpt = safe_excerpt_with_context(&source, 4_000, context);
            assert!(
                !excerpt.as_str().contains("abcDEF12345678901234"),
                "{file} leaked literal under {context:?}: {}",
                excerpt.as_str()
            );
            assert!(excerpt.as_str().contains("[REDACTED]"));
        }
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
                context: RedactionContext::Generic,
            },
        );

        assert!(excerpt.as_str().contains("const safe"));
        assert!(excerpt.as_str().contains("const secure"));
        assert!(excerpt.as_str().contains("[REDACTED]"));
        assert!(excerpt.as_str().chars().count() <= 80);
        assert!(
            !excerpt
                .as_str()
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
                jwt_attributes: None,
                token_boundary_attributes: None,
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

    #[test]
    fn sanitizes_jwt_identity_claim_attribute_values() {
        let output = sanitize_detection_output(DetectionOutput {
            artifacts: vec![Artifact {
                id: ArtifactId("artifact_jwt".to_string()),
                artifact_type: ArtifactType::AccessJwt,
                display_name: Some("access_jwt".to_string()),
                locations: Vec::new(),
                lifecycle_evidence: LifecycleEvidence::default(),
                confidence: Confidence::High,
                framework_hints: Vec::new(),
                cookie_attributes: None,
                jwt_attributes: Some(jwt_attributes_with_identity_value("person@example.com")),
                token_boundary_attributes: None,
            }],
            evidence: Vec::new(),
            diagnostics: Vec::new(),
        });

        let value = output.artifacts[0]
            .jwt_attributes
            .as_ref()
            .expect("jwt attributes should remain")
            .identity_claims
            .as_ref()
            .expect("identity claims should remain")
            .email
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

    fn jwt_attributes_with_identity_value(value: &str) -> JwtAttributes {
        let missing = JwtAttributeObservation {
            state: JwtAttributeState::Missing,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        JwtAttributes {
            operation: missing.clone(),
            algorithm: missing.clone(),
            key_reference: missing.clone(),
            issuer: missing.clone(),
            audience: missing.clone(),
            expiration: missing.clone(),
            signature_verification: missing.clone(),
            expiry_enforcement: missing.clone(),
            identity_claims: Some(JwtIdentityClaims {
                subject: missing.clone(),
                user_id: missing.clone(),
                tenant_id: missing.clone(),
                org_id: missing.clone(),
                workspace_id: missing.clone(),
                roles: missing.clone(),
                scopes: missing.clone(),
                groups: missing.clone(),
                email: JwtAttributeObservation {
                    state: JwtAttributeState::Present,
                    value: Some(value.to_string()),
                    evidence_ids: Vec::new(),
                    confidence: Confidence::High,
                },
                email_verified: missing.clone(),
                auth_method: missing.clone(),
                auth_class: missing,
            }),
        }
    }
}
