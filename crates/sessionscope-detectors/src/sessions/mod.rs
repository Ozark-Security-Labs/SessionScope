use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, Language, LifecycleEvidence, LifecycleStage,
    SanitizedExcerpt, SourceLocation, stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "session.lifecycle";
const REDACTION: &str = "[REDACTED]";

static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT|KEY)[A-Z0-9_]*\b")
        .expect("placeholder secret regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"#).expect("bearer regex should compile")
});
static SENSITIVE_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(token|secret|api[_-]?key|bearer|jwt|private[_-]?key)\s*[:=]\s*["'][^"']*["']"#,
    )
    .expect("sensitive literal regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct SessionLifecycleDetector;

impl Detector for SessionLifecycleDetector {
    fn id(&self) -> &'static str {
        DETECTOR_ID
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        match input.language {
            Language::JavaScript | Language::TypeScript => detect_javascript_like(input),
            Language::Python => detect_python(input),
            _ => DetectionOutput::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Signal {
    detector_id: &'static str,
    artifact_type: ArtifactType,
    display_name: String,
    framework_hint: &'static str,
    line: usize,
    column: usize,
    confidence: Confidence,
    dynamic: bool,
    excerpt: SanitizedExcerpt,
}

fn detect_javascript_like(input: &DetectorInput<'_>) -> DetectionOutput {
    let Some(tree) = parse_javascript_like(input, input.source) else {
        return DetectionOutput::default();
    };

    let mut signals = Vec::new();
    collect_js_signals(tree.root_node(), input.source, &mut signals);
    signals_to_output(input, signals)
}

fn detect_python(input: &DetectorInput<'_>) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let mut signals = Vec::new();
    collect_python_signals(tree.root_node(), input.source, &mut signals);
    signals_to_output(input, signals)
}

fn collect_js_signals(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    match node.kind() {
        "call_expression" => collect_js_call_signal(node, source, signals),
        "function_declaration" | "method_definition" => {
            if js_function_name(node, source)
                .as_deref()
                .is_some_and(|name| {
                    name == "DELETE" || name.to_ascii_lowercase().contains("logout")
                })
            {
                signals.push(signal(
                    "logout.handler",
                    ArtifactType::Unknown,
                    "logout",
                    "javascript",
                    node,
                    source,
                    Confidence::Medium,
                    true,
                ));
            }
        }
        "export_statement" => {
            let text = node_text(node, source);
            if text.contains("function DELETE") || text.contains("const DELETE") {
                signals.push(signal(
                    "logout.handler",
                    ArtifactType::Unknown,
                    "logout",
                    "nextjs",
                    node,
                    source,
                    Confidence::Medium,
                    true,
                ));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_signals(child, source, signals);
    }
}

fn collect_js_call_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let normalized = normalize_symbol(&text);

    if is_js_logout_route(&text) {
        signals.push(signal(
            "logout.handler",
            ArtifactType::Unknown,
            "logout",
            "express",
            node,
            source,
            Confidence::High,
            false,
        ));
    }

    if is_js_clear_cookie_call(node, source) {
        let name = first_call_string_argument(node, source).unwrap_or_else(|| "cookie".to_string());
        signals.push(signal(
            "logout.cookie_clear",
            cookie_artifact_type(&name),
            &name,
            js_cookie_clear_framework(&text),
            node,
            source,
            if name == "cookie" {
                Confidence::Medium
            } else {
                Confidence::High
            },
            name == "cookie",
        ));
        return;
    }

    if is_js_session_destroy_call(&normalized) {
        signals.push(signal(
            "logout.session_destroy",
            ArtifactType::SessionRecord,
            "session",
            "javascript",
            node,
            source,
            Confidence::High,
            false,
        ));
        return;
    }

    if is_js_provider_revoke_call(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            "logout.provider_revoke",
            token_artifact_type(&display_name),
            &display_name,
            "provider",
            node,
            source,
            Confidence::Medium,
            true,
        ));
        return;
    }

    if is_token_revoke_call(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            "logout.token_revoke",
            token_artifact_type(&display_name),
            &display_name,
            "javascript",
            node,
            source,
            Confidence::Medium,
            true,
        ));
    }
}

fn collect_python_signals(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    if node.kind() == "function_definition" {
        let name = child_by_field(node, "name").map(|name| node_text(name, source));
        let decorators = python_decorator_text(node, source);
        if name
            .as_deref()
            .is_some_and(|name| name.to_ascii_lowercase().contains("logout"))
            || decorators.to_ascii_lowercase().contains("/logout")
        {
            signals.push(signal(
                "logout.handler",
                ArtifactType::Unknown,
                "logout",
                python_framework_hint(&decorators),
                node,
                source,
                Confidence::High,
                false,
            ));
        }
    }

    if node.kind() == "call" {
        collect_python_call_signal(node, source, signals);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_signals(child, source, signals);
    }
}

fn collect_python_call_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let function = child_by_field(node, "function")
        .map(|function| node_text(function, source))
        .unwrap_or_default();
    let text = node_text(node, source);
    let normalized = normalize_symbol(&format!("{function} {text}"));

    if function.ends_with(".delete_cookie") || function == "delete_cookie" {
        let name = first_call_string_argument(node, source).unwrap_or_else(|| "cookie".to_string());
        signals.push(signal(
            "logout.cookie_clear",
            cookie_artifact_type(&name),
            &name,
            python_cookie_clear_framework(node),
            node,
            source,
            if name == "cookie" {
                Confidence::Medium
            } else {
                Confidence::High
            },
            name == "cookie",
        ));
        return;
    }

    if function == "logout" || function.ends_with(".logout") || normalized.contains("authlogout") {
        signals.push(signal(
            "logout.session_destroy",
            ArtifactType::SessionRecord,
            "session",
            "django",
            node,
            source,
            Confidence::High,
            false,
        ));
        return;
    }

    if is_python_session_destroy_call(&normalized) {
        signals.push(signal(
            "logout.session_destroy",
            ArtifactType::SessionRecord,
            "session",
            python_framework_hint(&text),
            node,
            source,
            Confidence::High,
            false,
        ));
        return;
    }

    if is_provider_revoke_text(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            "logout.provider_revoke",
            token_artifact_type(&display_name),
            &display_name,
            "provider",
            node,
            source,
            Confidence::Medium,
            true,
        ));
        return;
    }

    if is_token_revoke_call(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            "logout.token_revoke",
            token_artifact_type(&display_name),
            &display_name,
            "python",
            node,
            source,
            Confidence::Medium,
            true,
        ));
    }
}

fn signals_to_output(input: &DetectorInput<'_>, signals: Vec<Signal>) -> DetectionOutput {
    let mut output = DetectionOutput::default();
    let mut seen = BTreeSet::new();

    for signal in signals {
        let key = (
            signal.detector_id,
            signal.artifact_type,
            signal.display_name.clone(),
            signal.line,
            signal.column,
        );
        if !seen.insert(key) {
            continue;
        }

        let location = SourceLocation {
            path: input.path.to_string(),
            line: Some(signal.line),
            column: Some(signal.column),
        };
        let artifact_type = signal.artifact_type;
        let artifact_id = stable_artifact_id(&[
            signal.detector_id,
            artifact_type_part(artifact_type),
            input.path,
            &signal.line.to_string(),
            &signal.column.to_string(),
            &signal.display_name,
        ]);
        let evidence_id = stable_evidence_id(&[
            signal.detector_id,
            "revoke",
            input.path,
            &signal.line.to_string(),
            &signal.column.to_string(),
            &signal.display_name,
        ]);

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type,
            display_name: Some(signal.display_name),
            locations: vec![location.clone()],
            lifecycle_evidence: LifecycleEvidence {
                revoke: vec![evidence_id.clone()],
                ..LifecycleEvidence::default()
            },
            confidence: signal.confidence,
            framework_hints: vec![signal.framework_hint.to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
        });
        output.evidence.push(Evidence {
            id: evidence_id,
            lifecycle_stage: LifecycleStage::Revoke,
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

fn signal(
    detector_id: &'static str,
    artifact_type: ArtifactType,
    display_name: &str,
    framework_hint: &'static str,
    node: Node<'_>,
    source: &str,
    confidence: Confidence,
    dynamic: bool,
) -> Signal {
    Signal {
        detector_id,
        artifact_type,
        display_name: normalize_display_name(display_name),
        framework_hint,
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
        confidence,
        dynamic,
        excerpt: SanitizedExcerpt(sanitize_excerpt(&node_text(node, source))),
    }
}

fn parse_javascript_like(input: &DetectorInput<'_>, source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = match input.language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript if input.path.ends_with(".tsx") => {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        }
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => return None,
    };
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

fn parse_python(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

fn is_js_logout_route(text: &str) -> bool {
    let normalized = normalize_symbol(text);
    (normalized.contains("app.post") || normalized.contains("router.post"))
        && normalized.contains("logout")
}

fn is_js_clear_cookie_call(node: Node<'_>, source: &str) -> bool {
    let function = child_by_field(node, "function")
        .map(|function| node_text(function, source))
        .unwrap_or_default();
    function.ends_with(".clearCookie")
        || function.ends_with(".clear_cookie")
        || function == "clearCookie"
        || (function.ends_with(".delete") && node_text(node, source).contains("cookies()"))
}

fn js_cookie_clear_framework(text: &str) -> &'static str {
    if text.contains("cookies()") {
        "nextjs"
    } else {
        "express"
    }
}

fn is_js_session_destroy_call(normalized: &str) -> bool {
    normalized.contains("session.destroy")
        || normalized.contains("req.session.destroy")
        || normalized.contains("request.session.destroy")
        || normalized.contains("session.invalidate")
        || normalized.contains("session.revoke")
        || normalized.contains("destroysession")
        || normalized.contains("invalidatesession")
        || normalized.contains("revokesession")
        || (normalized.contains("session")
            && (normalized.contains("destroy")
                || normalized.contains("invalidate")
                || normalized.contains("revoke")))
}

fn is_python_session_destroy_call(normalized: &str) -> bool {
    normalized.contains("session.flush")
        || normalized.contains("session.delete")
        || normalized.contains("session.destroy")
        || normalized.contains("revoke_session")
        || normalized.contains("revokesession")
        || normalized.contains("revoke_user_sessions")
        || normalized.contains("revokeusersessions")
        || normalized.contains("invalidate_session")
        || normalized.contains("invalidatesession")
        || normalized.contains("destroy_session")
        || normalized.contains("destroysession")
}

fn is_js_provider_revoke_call(normalized: &str) -> bool {
    is_provider_revoke_text(normalized)
}

fn is_provider_revoke_text(normalized: &str) -> bool {
    normalized.contains("provider.revoke")
        || normalized.contains("auth0.revoke")
        || normalized.contains("okta.revoke")
        || normalized.contains("oauth.revoke")
        || normalized.contains("supabase.auth.signout")
        || normalized.contains("clerk.sessions.revoke")
        || normalized.contains("identityprovider.revoke")
}

fn is_token_revoke_call(normalized: &str) -> bool {
    (normalized.contains("revoke")
        || normalized.contains("invalidate")
        || normalized.contains("denylist")
        || normalized.contains("blacklist")
        || normalized.contains("destroy"))
        && (normalized.contains("token")
            || normalized.contains("jwt")
            || normalized.contains("refresh")
            || normalized.contains("bearer")
            || normalized.contains("session"))
}

fn token_display_name(normalized: &str) -> String {
    if normalized.contains("refresh") {
        "refresh_token".to_string()
    } else if normalized.contains("access") {
        "access_token".to_string()
    } else if normalized.contains("reset") {
        "reset_token".to_string()
    } else if normalized.contains("session") {
        "session".to_string()
    } else {
        "token".to_string()
    }
}

fn token_artifact_type(display_name: &str) -> ArtifactType {
    if display_name.contains("session") {
        ArtifactType::SessionRecord
    } else if display_name.contains("refresh") {
        ArtifactType::RefreshJwt
    } else if display_name.contains("access") {
        ArtifactType::AccessJwt
    } else if display_name.contains("reset") {
        ArtifactType::PasswordResetToken
    } else {
        ArtifactType::Unknown
    }
}

fn cookie_artifact_type(name: &str) -> ArtifactType {
    let normalized = normalize_display_name(name);
    if normalized.contains("session") || normalized == "sid" || normalized.ends_with("_sid") {
        ArtifactType::SessionCookie
    } else if normalized.contains("signed") {
        ArtifactType::SignedCookie
    } else {
        ArtifactType::Unknown
    }
}

fn first_call_string_argument(node: Node<'_>, source: &str) -> Option<String> {
    let arguments = child_by_field(node, "arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments.named_children(&mut cursor) {
        if let Some(value) = string_literal_value(child, source) {
            return Some(value);
        }
        if child.kind() == "keyword_argument" {
            let mut keyword_cursor = child.walk();
            for keyword_child in child.named_children(&mut keyword_cursor) {
                if let Some(value) = string_literal_value(keyword_child, source) {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn string_literal_value(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "string" | "string_fragment" | "string_literal" => {
            Some(strip_quotes(&node_text(node, source)))
        }
        _ => None,
    }
}

fn js_function_name(node: Node<'_>, source: &str) -> Option<String> {
    child_by_field(node, "name").map(|name| node_text(name, source))
}

fn python_decorator_text(node: Node<'_>, source: &str) -> String {
    let mut parts = Vec::new();
    let mut current = node.prev_named_sibling();
    while let Some(previous) = current {
        if previous.kind() != "decorator" {
            break;
        }
        parts.push(node_text(previous, source));
        current = previous.prev_named_sibling();
    }
    parts.join("\n")
}

fn python_framework_hint(text: &str) -> &'static str {
    let normalized = text.to_ascii_lowercase();
    if normalized.contains("fastapi")
        || normalized.contains("@app.")
        || normalized.contains("@router.")
    {
        "fastapi"
    } else if normalized.contains("django") || normalized.contains("logout") {
        "django"
    } else {
        "python"
    }
}

fn python_cookie_clear_framework(node: Node<'_>) -> &'static str {
    let mut current = Some(node);
    while let Some(node) = current {
        if node.kind() == "function_definition" {
            return "python";
        }
        current = node.parent();
    }
    "python"
}

fn child_by_field<'a>(node: Node<'a>, field: &str) -> Option<Node<'a>> {
    node.child_by_field_name(field)
}

fn node_text(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes()).unwrap_or("").to_string()
}

fn strip_quotes(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn sanitize_excerpt(excerpt: &str) -> String {
    let mut redacted = PLACEHOLDER_SECRET_RE
        .replace_all(excerpt, REDACTION)
        .to_string();
    redacted = JWT_RE.replace_all(&redacted, REDACTION).to_string();
    redacted = BEARER_RE.replace_all(&redacted, REDACTION).to_string();
    SENSITIVE_LITERAL_RE
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
            let key = captures.get(1).map(|key| key.as_str()).unwrap_or("token");
            format!("{key}: \"{REDACTION}\"")
        })
        .to_string()
}

fn normalize_symbol(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/'))
        .collect::<String>()
        .to_ascii_lowercase()
}

fn normalize_display_name(value: &str) -> String {
    let normalized = value.trim().trim_matches('"').trim_matches('\'');
    normalized
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

fn artifact_type_part(artifact_type: ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::SessionCookie => "session_cookie",
        ArtifactType::SignedCookie => "signed_cookie",
        ArtifactType::AccessJwt => "access_jwt",
        ArtifactType::RefreshJwt => "refresh_jwt",
        ArtifactType::OpaqueBearerToken => "opaque_bearer_token",
        ArtifactType::ApiKey => "api_key",
        ArtifactType::PasswordResetToken => "password_reset_token",
        ArtifactType::EmailVerificationToken => "email_verification_token",
        ArtifactType::SessionRecord => "session_record",
        ArtifactType::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(language: Language, source: &str) -> DetectionOutput {
        SessionLifecycleDetector.detect(&DetectorInput {
            path: match language {
                Language::Python => "app.py",
                Language::TypeScript => "app.ts",
                _ => "app.js",
            },
            language,
            source,
        })
    }

    #[test]
    fn detects_express_logout_clear_destroy_and_refresh_revoke() {
        let output = detect(
            Language::TypeScript,
            r#"
app.post("/logout", (request, response) => {
  response.clearCookie("session");
  request.session.destroy();
  revokeRefreshToken(request.cookies.refresh_token);
});
"#,
        );

        assert_detector(&output, "logout.handler");
        assert_detector(&output, "logout.cookie_clear");
        assert_detector(&output, "logout.session_destroy");
        assert_detector(&output, "logout.token_revoke");
        assert!(artifact_named(&output, "session").is_some());
        assert!(artifact_named(&output, "refresh_token").is_some());
    }

    #[test]
    fn detects_nextjs_cookie_delete() {
        let output = detect(
            Language::TypeScript,
            r#"
export async function DELETE() {
  cookies().delete("session");
}
"#,
        );

        assert_detector(&output, "logout.handler");
        assert_detector(&output, "logout.cookie_clear");
        assert!(
            output
                .artifacts
                .iter()
                .any(|artifact| artifact.framework_hints == vec!["nextjs".to_string()])
        );
    }

    #[test]
    fn detects_fastapi_cookie_delete_and_session_revoke() {
        let output = detect(
            Language::Python,
            r#"
@app.post("/logout")
def logout(response):
    response.delete_cookie("session")
    revoke_session(current_user.id)
"#,
        );

        assert_detector(&output, "logout.handler");
        assert_detector(&output, "logout.cookie_clear");
        assert_detector(&output, "logout.session_destroy");
    }

    #[test]
    fn detects_django_logout_cookie_delete_and_user_session_revoke() {
        let output = detect(
            Language::Python,
            r#"
def logout_view(request):
    logout(request)
    response.delete_cookie("sessionid")
    revoke_user_sessions(request.user)
"#,
        );

        assert_detector(&output, "logout.handler");
        assert_detector(&output, "logout.cookie_clear");
        assert_detector(&output, "logout.session_destroy");
    }

    #[test]
    fn detects_provider_abstractions_and_local_wrappers() {
        let js_output = detect(
            Language::TypeScript,
            r#"
authProvider.revoke(refreshToken);
invalidateRefreshToken(previousRefreshToken);
"#,
        );
        let py_output = detect(
            Language::Python,
            r#"
provider.revoke(refresh_token)
destroy_refresh_token(refresh_token)
"#,
        );

        assert_detector(&js_output, "logout.provider_revoke");
        assert_detector(&js_output, "logout.token_revoke");
        assert_detector(&py_output, "logout.provider_revoke");
        assert_detector(&py_output, "logout.token_revoke");
    }

    #[test]
    fn ignores_comments_and_strings_and_redacts_placeholders() {
        let output = detect(
            Language::TypeScript,
            r#"
// response.clearCookie("session")
const sample = "provider.revoke(PLACEHOLDER_REFRESH_TOKEN)";
app.post("/logout", () => revokeRefreshToken("PLACEHOLDER_REFRESH_TOKEN"));
"#,
        );

        assert_eq!(
            output
                .evidence
                .iter()
                .filter(|evidence| evidence.detector_id == "logout.cookie_clear")
                .count(),
            0
        );
        assert_detector(&output, "logout.token_revoke");
        let text = output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.0.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!text.contains("PLACEHOLDER_REFRESH_TOKEN"));
        assert!(text.contains(REDACTION));
    }

    fn assert_detector(output: &DetectionOutput, detector_id: &str) {
        assert!(
            output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == detector_id),
            "expected detector {detector_id} in {:?}",
            output.evidence
        );
    }

    fn artifact_named<'a>(output: &'a DetectionOutput, display_name: &str) -> Option<&'a Artifact> {
        output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some(display_name))
    }
}
