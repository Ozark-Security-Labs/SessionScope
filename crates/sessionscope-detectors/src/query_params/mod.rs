use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, Language, LifecycleEvidence, LifecycleStage,
    SanitizedExcerpt, SourceLocation, stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "query_param.token";
const REDACTION: &str = "[REDACTED]";
const TREE_SITTER_MAX_DEPTH: usize = 256;

static QUOTED_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
        .expect("quoted literal regex should compile")
});
static TEMPLATE_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"`(?:\\.|[^`\\])*`"#).expect("template literal regex should compile")
});
static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT|KEY)[A-Z0-9_]*\b")
        .expect("placeholder regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static QUERY_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)([?&](?:access[_-]?token|id[_-]?token|refresh[_-]?token|api[_-]?key|apikey|service[_-]?token|client[_-]?token|reset[_-]?token|verification[_-]?token|email[_-]?token|token)=)([^&#\s"']+)"#,
    )
    .expect("query value regex should compile")
});
static JS_SEARCH_GET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:searchParams|query)\s*\.\s*get\s*\(\s*["']([^"']+)["']"#)
        .expect("JS search params regex should compile")
});
static JS_SEARCH_GET_DYNAMIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:searchParams|query)\s*\.\s*get\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)"#)
        .expect("JS dynamic search params regex should compile")
});
static JS_QUERY_DOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:req|request|context)\s*\.\s*query\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)"#)
        .expect("JS query dot regex should compile")
});
static JS_QUERY_BRACKET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:req|request|context)\s*\.\s*query\s*\[\s*["']([^"']+)["']\s*\]"#)
        .expect("JS query bracket regex should compile")
});
static JS_QUERY_BRACKET_DYNAMIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:req|request|context)\s*\.\s*query\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]"#)
        .expect("JS dynamic query bracket regex should compile")
});
static PY_QUERY_GET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:request\.)?(?:query_params|GET)\s*\.\s*get\s*\(\s*["']([^"']+)["']"#)
        .expect("Python query get regex should compile")
});
static PY_QUERY_GET_DYNAMIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:request\.)?(?:query_params|GET)\s*\.\s*get\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)"#)
        .expect("Python dynamic query get regex should compile")
});
static PY_QUERY_BRACKET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:request\.)?(?:query_params|GET)\s*\[\s*["']([^"']+)["']\s*\]"#)
        .expect("Python query bracket regex should compile")
});
static PY_QUERY_BRACKET_DYNAMIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:request\.)?(?:query_params|GET)\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]"#)
        .expect("Python dynamic query bracket regex should compile")
});
static PY_QUERY_ALIAS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)alias\s*=\s*["']([^"']+)["']"#).expect("Query alias regex should compile")
});
static PY_PARAM_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::|=)"#)
        .expect("Python parameter name regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct QueryParameterTokenDetector;

impl Detector for QueryParameterTokenDetector {
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
    let mut depth_skipped = false;
    collect_js_signals(
        tree.root_node(),
        input.source,
        &mut signals,
        0,
        &mut depth_skipped,
    );
    let mut output = signals_to_output(input, signals);
    if depth_skipped {
        output.evidence.push(depth_limit_evidence(input));
    }
    output
}

fn detect_python(input: &DetectorInput<'_>) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let mut signals = Vec::new();
    let mut depth_skipped = false;
    collect_python_signals(
        tree.root_node(),
        input.source,
        &mut signals,
        0,
        &mut depth_skipped,
    );
    let mut output = signals_to_output(input, signals);
    if depth_skipped {
        output.evidence.push(depth_limit_evidence(input));
    }
    output
}

fn collect_js_signals(
    node: Node<'_>,
    source: &str,
    signals: &mut Vec<Signal>,
    depth: usize,
    depth_skipped: &mut bool,
) {
    if depth > TREE_SITTER_MAX_DEPTH {
        *depth_skipped = true;
        return;
    }
    match node.kind() {
        "call_expression"
        | "member_expression"
        | "subscript_expression"
        | "variable_declarator"
        | "lexical_declaration"
        | "assignment_expression" => collect_js_query_signal(node, source, signals),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_signals(child, source, signals, depth + 1, depth_skipped);
    }
}

fn collect_python_signals(
    node: Node<'_>,
    source: &str,
    signals: &mut Vec<Signal>,
    depth: usize,
    depth_skipped: &mut bool,
) {
    if depth > TREE_SITTER_MAX_DEPTH {
        *depth_skipped = true;
        return;
    }
    match node.kind() {
        "call"
        | "subscript"
        | "assignment"
        | "default_parameter"
        | "typed_default_parameter"
        | "keyword_argument"
        | "parameters" => collect_python_query_signal(node, source, signals),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_signals(child, source, signals, depth + 1, depth_skipped);
    }
}

fn collect_js_query_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let context = node_context_text(node, source);

    for parameter in static_js_query_names(&text) {
        push_static_signal(
            node,
            source,
            &context,
            &parameter,
            js_framework_hint(&context),
            signals,
        );
    }

    for parameter in js_destructured_query_names(&text) {
        push_static_signal(
            node,
            source,
            &context,
            &parameter,
            js_framework_hint(&context),
            signals,
        );
    }

    for name in dynamic_js_query_names(&text) {
        push_dynamic_signal(
            node,
            source,
            &context,
            &name,
            js_framework_hint(&context),
            signals,
        );
    }
}

fn collect_python_query_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let context = node_context_text(node, source);

    for parameter in static_python_query_names(&text) {
        push_static_signal(
            node,
            source,
            &context,
            &parameter,
            python_framework_hint(&context),
            signals,
        );
    }

    for name in dynamic_python_query_names(&text) {
        push_dynamic_signal(
            node,
            source,
            &context,
            &name,
            python_framework_hint(&context),
            signals,
        );
    }
}

fn push_static_signal(
    node: Node<'_>,
    source: &str,
    context: &str,
    parameter: &str,
    framework_hint: &'static str,
    signals: &mut Vec<Signal>,
) {
    let normalized_parameter = normalize_parameter(parameter);
    if !is_relevant_query_token_name(&normalized_parameter) {
        return;
    }

    let artifact_type = artifact_type_for_query_name(&normalized_parameter, context);
    let display_name = display_name_for_query_name(&normalized_parameter, artifact_type);
    let (line, column) = node_line_column(node);
    signals.push(Signal {
        detector_id: "query_param.read",
        artifact_type,
        display_name,
        framework_hint,
        line,
        column,
        confidence: Confidence::High,
        dynamic: false,
        excerpt: SanitizedExcerpt::from_sanitized(sanitize_excerpt(&node_text(node, source))),
    });
}

fn push_dynamic_signal(
    node: Node<'_>,
    source: &str,
    context: &str,
    variable_name: &str,
    framework_hint: &'static str,
    signals: &mut Vec<Signal>,
) {
    let normalized_variable = normalize_parameter(variable_name);
    if !is_dynamic_query_name_relevant(&normalized_variable, context) {
        return;
    }

    let artifact_type = artifact_type_for_query_name(&normalized_variable, context);
    let display_name = if artifact_type == ArtifactType::UnknownToken {
        "dynamic_query_token".to_string()
    } else {
        display_name_for_query_name(&normalized_variable, artifact_type)
    };
    let (line, column) = node_line_column(node);
    signals.push(Signal {
        detector_id: "query_param.read.dynamic",
        artifact_type,
        display_name,
        framework_hint,
        line,
        column,
        confidence: Confidence::Medium,
        dynamic: true,
        excerpt: SanitizedExcerpt::from_sanitized(sanitize_excerpt(&node_text(node, source))),
    });
}

fn static_js_query_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    names.extend(captures(&JS_SEARCH_GET_RE, text));
    names.extend(captures(&JS_QUERY_DOT_RE, text));
    names.extend(captures(&JS_QUERY_BRACKET_RE, text));
    names
}

fn dynamic_js_query_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    names.extend(captures(&JS_SEARCH_GET_DYNAMIC_RE, text));
    names.extend(captures(&JS_QUERY_BRACKET_DYNAMIC_RE, text));
    names
        .into_iter()
        .filter(|name| !name.starts_with('"') && !name.starts_with('\''))
        .collect()
}

fn js_destructured_query_names(text: &str) -> Vec<String> {
    let normalized = normalize_symbol_without_literals(text);
    if !(normalized.contains("req.query")
        || normalized.contains("request.query")
        || normalized.contains("context.query"))
    {
        return Vec::new();
    }

    let Some(open) = text.find('{') else {
        return Vec::new();
    };
    let Some(close) = matching_brace(text, open) else {
        return Vec::new();
    };

    destructured_names(&text[open + 1..close])
}

fn matching_brace(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in text[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn destructured_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for part in split_top_level_commas(text) {
        let trimmed = part.trim().trim_start_matches("...").trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(open) = trimmed.find('{') {
            names.extend(destructured_names(
                &trimmed[open + 1..trimmed.len().saturating_sub(1)],
            ));
            continue;
        }
        let name = trimmed.split(':').next().unwrap_or(trimmed).trim();
        if !name.is_empty() {
            names.push(name.to_string());
        }
    }
    names
}

fn split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, ch) in text.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&text[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

fn static_python_query_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    names.extend(captures(&PY_QUERY_GET_RE, text));
    names.extend(captures(&PY_QUERY_BRACKET_RE, text));
    if text.contains("Query(") {
        if let Some(alias) = PY_QUERY_ALIAS_RE
            .captures(text)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            names.push(alias);
        } else if let Some(name) = PY_PARAM_NAME_RE
            .captures(text)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            names.push(name);
        }
    }
    names
}

fn dynamic_python_query_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    names.extend(captures(&PY_QUERY_GET_DYNAMIC_RE, text));
    names.extend(captures(&PY_QUERY_BRACKET_DYNAMIC_RE, text));
    names
        .into_iter()
        .filter(|name| !name.starts_with('"') && !name.starts_with('\''))
        .collect()
}

fn captures(regex: &Regex, text: &str) -> Vec<String> {
    regex
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).map(|capture| capture.as_str().to_string()))
        .collect()
}

fn signals_to_output(input: &DetectorInput<'_>, signals: Vec<Signal>) -> DetectionOutput {
    let mut output = DetectionOutput::default();
    let mut seen = BTreeSet::new();

    for signal in signals {
        let line_part = signal.line.to_string();
        let artifact_part = artifact_type_part(signal.artifact_type);
        let evidence_id = stable_evidence_id(&[
            DETECTOR_ID,
            signal.detector_id,
            "transmit",
            input.path,
            &line_part,
            signal.display_name.as_str(),
        ]);
        if !seen.insert(evidence_id.0.clone()) {
            continue;
        }

        let artifact_id = stable_artifact_id(&[
            DETECTOR_ID,
            artifact_part,
            input.path,
            signal.display_name.as_str(),
        ]);
        let mut lifecycle_evidence = LifecycleEvidence::default();
        lifecycle_evidence.transmit.push(evidence_id.clone());
        let location = SourceLocation {
            path: input.path.to_string(),
            line: Some(signal.line),
            column: Some(signal.column),
        };

        let artifact = Artifact {
            id: artifact_id,
            artifact_type: signal.artifact_type,
            display_name: Some(signal.display_name),
            locations: vec![location.clone()],
            lifecycle_evidence,
            confidence: signal.confidence,
            framework_hints: vec![signal.framework_hint.to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        };
        merge_artifact(&mut output.artifacts, artifact);
        output.evidence.push(Evidence {
            id: evidence_id,
            lifecycle_stage: LifecycleStage::Transmit,
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

fn depth_limit_evidence(input: &DetectorInput<'_>) -> Evidence {
    let depth_part = TREE_SITTER_MAX_DEPTH.to_string();
    Evidence {
        id: stable_evidence_id(&[
            DETECTOR_ID,
            "detector.depth_limit_skipped",
            input.path,
            depth_part.as_str(),
        ]),
        lifecycle_stage: LifecycleStage::Introspect,
        location: SourceLocation {
            path: input.path.to_string(),
            line: None,
            column: None,
        },
        detector_id: "detector.depth_limit_skipped".to_string(),
        confidence: Confidence::Low,
        excerpt: Some(SanitizedExcerpt::from_sanitized(
            "tree-sitter traversal depth limit reached".to_string(),
        )),
        dynamic: true,
        framework_default: false,
    }
}

fn merge_artifact(artifacts: &mut Vec<Artifact>, artifact: Artifact) {
    let Some(existing) = artifacts
        .iter_mut()
        .find(|existing| existing.id == artifact.id)
    else {
        artifacts.push(artifact);
        return;
    };

    existing.locations.extend(artifact.locations);
    existing.locations.sort();
    existing.locations.dedup();
    merge_lifecycle_evidence(
        &mut existing.lifecycle_evidence,
        artifact.lifecycle_evidence,
    );
    existing.framework_hints.extend(artifact.framework_hints);
    existing.framework_hints.sort();
    existing.framework_hints.dedup();
    if artifact.confidence > existing.confidence {
        existing.confidence = artifact.confidence;
    }
}

fn merge_lifecycle_evidence(existing: &mut LifecycleEvidence, incoming: LifecycleEvidence) {
    existing.issue.extend(incoming.issue);
    existing.store.extend(incoming.store);
    existing.transmit.extend(incoming.transmit);
    existing.validate.extend(incoming.validate);
    existing.refresh.extend(incoming.refresh);
    existing.revoke.extend(incoming.revoke);
    existing.expire.extend(incoming.expire);
    existing.introspect.extend(incoming.introspect);
    for ids in [
        &mut existing.issue,
        &mut existing.store,
        &mut existing.transmit,
        &mut existing.validate,
        &mut existing.refresh,
        &mut existing.revoke,
        &mut existing.expire,
        &mut existing.introspect,
    ] {
        ids.sort();
        ids.dedup();
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

fn artifact_type_for_query_name(parameter: &str, context: &str) -> ArtifactType {
    let normalized_context = normalize_symbol_without_literals(context);
    if reset_context(parameter, &normalized_context) {
        ArtifactType::PasswordResetToken
    } else if verification_context(parameter, &normalized_context) {
        ArtifactType::EmailVerificationToken
    } else if matches!(parameter, "refresh_token" | "refresh_jwt") {
        ArtifactType::RefreshJwt
    } else if matches!(parameter, "access_token" | "id_token" | "access_jwt") {
        ArtifactType::AccessJwt
    } else if matches!(parameter, "api_key" | "apikey" | "x_api_key" | "xapikey") {
        ArtifactType::ApiKey
    } else if parameter.contains("service")
        || parameter.contains("client")
        || parameter.contains("machine")
        || parameter.contains("internal")
    {
        ArtifactType::ServiceToken
    } else if parameter.contains("bearer") || parameter.contains("authorization") {
        ArtifactType::OpaqueBearerToken
    } else {
        ArtifactType::UnknownToken
    }
}

fn display_name_for_query_name(parameter: &str, artifact_type: ArtifactType) -> String {
    match artifact_type {
        ArtifactType::PasswordResetToken => "password_reset_token".to_string(),
        ArtifactType::EmailVerificationToken => "email_verification_token".to_string(),
        _ if parameter == "apikey" => "api_key".to_string(),
        _ if parameter == "xapikey" => "x_api_key".to_string(),
        _ => parameter.to_string(),
    }
}

fn is_relevant_query_token_name(parameter: &str) -> bool {
    is_token_like_query_name(parameter) && !is_ignored_query_name(parameter)
}

fn is_dynamic_query_name_relevant(parameter: &str, context: &str) -> bool {
    !is_ignored_query_name(parameter)
        && !is_ignored_dynamic_query_name(parameter)
        && (is_token_like_query_name(parameter)
            || normalize_symbol_without_literals(context).contains("token"))
}

fn is_token_like_query_name(parameter: &str) -> bool {
    matches!(
        parameter,
        "token"
            | "access_token"
            | "id_token"
            | "refresh_token"
            | "api_key"
            | "apikey"
            | "x_api_key"
            | "xapikey"
            | "service_token"
            | "client_token"
            | "reset_token"
            | "verification_token"
            | "email_token"
            | "email_verification_token"
            | "password_reset_token"
            | "bearer_token"
            | "authorization"
    ) || parameter.ends_with("_token")
        || parameter.ends_with("token")
        || parameter.ends_with("_key")
}

fn is_ignored_query_name(parameter: &str) -> bool {
    matches!(
        parameter,
        "page_token"
            | "next_token"
            | "previous_token"
            | "prev_token"
            | "continuation_token"
            | "pagination_token"
            | "cursor_token"
            | "offset_token"
            | "limit_token"
            | "filter_token"
            | "sort_token"
            | "search_token"
            | "idempotency_key"
            | "dedupe_key"
            | "request_key"
            | "page_key"
            | "cursor_key"
            | "filter_key"
            | "csrf_token"
            | "xsrf_token"
            | "state"
            | "code"
            | "search"
            | "sort"
            | "page"
            | "cursor"
            | "next"
    )
}

fn is_ignored_dynamic_query_name(parameter: &str) -> bool {
    [
        "page",
        "pagination",
        "cursor",
        "offset",
        "limit",
        "filter",
        "sort",
        "search",
        "previous",
        "prev",
        "next",
        "continuation",
        "idempotency",
        "dedupe",
        "request",
        "csrf",
        "xsrf",
        "state",
        "code",
    ]
    .iter()
    .any(|ignored| parameter.contains(ignored))
}

fn reset_context(parameter: &str, normalized_context: &str) -> bool {
    parameter.contains("reset")
        || parameter.contains("password")
        || (parameter == "token"
            && (normalized_context.contains("reset")
                || normalized_context.contains("forgotpassword")
                || normalized_context.contains("password")))
}

fn verification_context(parameter: &str, normalized_context: &str) -> bool {
    parameter.contains("verification")
        || parameter.contains("verify")
        || parameter.contains("email")
        || (parameter == "token"
            && (normalized_context.contains("verify")
                || normalized_context.contains("verification")
                || normalized_context.contains("confirm")
                || normalized_context.contains("email")))
}

fn js_framework_hint(context: &str) -> &'static str {
    let normalized = normalize_symbol_without_literals(context);
    if normalized.contains("nexturl") || normalized.contains("searchparams") {
        "nextjs"
    } else if normalized.contains("req.query") || normalized.contains("app.get") {
        "express"
    } else {
        "javascript"
    }
}

fn python_framework_hint(context: &str) -> &'static str {
    let normalized = normalize_symbol_without_literals(context);
    if normalized.contains("query_params") {
        "fastapi"
    } else if normalized.contains("request.get") || normalized.contains("request.get.get") {
        "django"
    } else if normalized.contains("query") {
        "fastapi"
    } else {
        "python"
    }
}

fn normalize_parameter(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
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

fn sanitize_excerpt(excerpt: &str) -> String {
    let mut redacted = QUERY_VALUE_RE
        .replace_all(excerpt, format!("${{1}}{REDACTION}"))
        .to_string();
    redacted = PLACEHOLDER_SECRET_RE
        .replace_all(&redacted, REDACTION)
        .to_string();
    redacted = JWT_RE.replace_all(&redacted, REDACTION).to_string();
    if should_redact_string_literals(&redacted) {
        redacted = QUOTED_LITERAL_RE
            .replace_all(&redacted, format!("\"{REDACTION}\""))
            .to_string();
    }
    redacted
}

fn should_redact_string_literals(excerpt: &str) -> bool {
    let normalized = normalize_symbol_without_literals(excerpt);
    normalized.contains("placeholder")
        || normalized.contains("bearer")
        || normalized.contains("secret")
        || normalized.contains("?token")
        || normalized.contains("access_token=")
        || normalized.contains("api_key=")
}

fn node_context_text(node: Node<'_>, source: &str) -> String {
    let mut current = node.parent();
    for _ in 0..8 {
        let Some(candidate) = current else {
            break;
        };
        if matches!(
            candidate.kind(),
            "function_declaration"
                | "function"
                | "arrow_function"
                | "method_definition"
                | "call_expression"
                | "decorated_definition"
                | "function_definition"
                | "program"
                | "module"
        ) {
            let text = node_text(candidate, source);
            if text.len() <= 2_000 {
                return text;
            }
        }
        current = candidate.parent();
    }
    node_text(node, source)
}

fn node_line_column(node: Node<'_>) -> (usize, usize) {
    let position = node.start_position();
    (position.row + 1, position.column + 1)
}

fn node_text(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes())
        .unwrap_or_default()
        .to_string()
}

fn normalize_symbol_without_literals(value: &str) -> String {
    normalize_symbol(&strip_string_literals(value))
}

fn normalize_symbol(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/'))
        .collect::<String>()
        .to_ascii_lowercase()
}

fn strip_string_literals(value: &str) -> String {
    let without_templates = TEMPLATE_LITERAL_RE.replace_all(value, "``");
    QUOTED_LITERAL_RE
        .replace_all(&without_templates, "\"\"")
        .to_string()
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
        ArtifactType::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{ArtifactType, Language};

    use super::*;

    fn detect(language: Language, source: &str) -> DetectionOutput {
        QueryParameterTokenDetector.detect(&DetectorInput {
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
    fn detects_express_and_next_query_token_reads() {
        let output = detect(
            Language::TypeScript,
            r#"
app.get("/callback", (req, res) => {
  const accessToken = req.query.access_token;
  const apiKey = req.query["api_key"];
  const { id_token: idToken } = req.query;
});
export async function GET(request: Request) {
  return request.nextUrl.searchParams.get("refresh_token");
}
"#,
        );

        assert_artifact(&output, ArtifactType::AccessJwt, "access_token");
        assert_artifact(&output, ArtifactType::ApiKey, "api_key");
        assert_artifact(&output, ArtifactType::AccessJwt, "id_token");
        assert_artifact(&output, ArtifactType::RefreshJwt, "refresh_token");
        assert_detector(&output, "query_param.read");
    }

    #[test]
    fn detects_fastapi_and_django_query_token_reads() {
        let output = detect(
            Language::Python,
            r#"
@app.get("/callback")
def callback(access_token: str = Query(None), api_key: str = Query(alias="api_key")):
    return access_token

def django_view(request):
    token = request.GET.get("token")
    refresh = request.query_params.get("refresh_token")
    return token or refresh
"#,
        );

        assert_artifact(&output, ArtifactType::AccessJwt, "access_token");
        assert_artifact(&output, ArtifactType::ApiKey, "api_key");
        assert_artifact(&output, ArtifactType::UnknownToken, "token");
        assert_artifact(&output, ArtifactType::RefreshJwt, "refresh_token");
    }

    #[test]
    fn maps_reset_and_verification_query_flows() {
        let output = detect(
            Language::TypeScript,
            r#"
app.get("/reset-password", (req, res) => {
  return resetPassword(req.query.token);
});
app.get("/verify-email", (req, res) => {
  return verifyEmail(req.query.token);
});
"#,
        );

        assert_artifact(
            &output,
            ArtifactType::PasswordResetToken,
            "password_reset_token",
        );
        assert_artifact(
            &output,
            ArtifactType::EmailVerificationToken,
            "email_verification_token",
        );
    }

    #[test]
    fn dynamic_query_names_are_medium_confidence() {
        let output = detect(
            Language::TypeScript,
            r#"
const tokenParamName = getConfiguredTokenParam();
const token = req.query[tokenParamName];
"#,
        );

        let evidence = output
            .evidence
            .iter()
            .find(|evidence| evidence.detector_id == "query_param.read.dynamic")
            .expect("dynamic evidence");
        assert_eq!(evidence.confidence, Confidence::Medium);
        assert!(evidence.dynamic);
    }

    #[test]
    fn ignores_comments_strings_and_non_auth_query_names() {
        let output = detect(
            Language::TypeScript,
            r#"
// const token = req.query.access_token;
const sample = "request.GET.get('token')";
const pageToken = req.query.page_token;
const state = req.query.state;
const code = req.query.code;
"#,
        );

        assert!(output.artifacts.is_empty(), "{:?}", output.artifacts);
        assert!(output.evidence.is_empty(), "{:?}", output.evidence);
    }

    #[test]
    fn ignores_pagination_idempotency_and_dynamic_ignored_names() {
        let output = detect(
            Language::TypeScript,
            r#"
const page = req.query.page_token;
const idem = req.query.idempotency_key;
const cursorName = "cursor_token";
const cursor = req.query[cursorName];
"#,
        );

        assert!(output.artifacts.is_empty(), "{:?}", output.artifacts);
        assert!(output.evidence.is_empty(), "{:?}", output.evidence);
    }

    #[test]
    fn detects_nested_destructured_query_token_names() {
        let output = detect(
            Language::TypeScript,
            r#"
const { paging: { page_token }, auth: { access_token } } = req.query;
"#,
        );

        assert_artifact(&output, ArtifactType::AccessJwt, "access_token");
        assert!(
            !output
                .artifacts
                .iter()
                .any(|artifact| artifact.display_name.as_deref() == Some("page_token"))
        );
    }

    #[test]
    fn merges_duplicate_query_artifacts() {
        let output = detect(
            Language::TypeScript,
            r#"
const one = req.query.access_token;
const two = req.query["access_token"];
"#,
        );

        let access_artifacts = output
            .artifacts
            .iter()
            .filter(|artifact| artifact.display_name.as_deref() == Some("access_token"))
            .collect::<Vec<_>>();
        assert_eq!(access_artifacts.len(), 1, "{:?}", output.artifacts);
        assert_eq!(access_artifacts[0].lifecycle_evidence.transmit.len(), 2);
    }

    #[test]
    fn emits_depth_limit_evidence_for_deep_trees() {
        let source = format!(
            "{}req.query.access_token{}",
            "(".repeat(270),
            ")".repeat(270)
        );
        let output = detect(Language::TypeScript, &source);

        assert!(
            output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "detector.depth_limit_skipped")
        );
    }

    #[test]
    fn redacts_query_values_and_placeholder_tokens() {
        let output = detect(
            Language::TypeScript,
            r#"
app.get("/callback?access_token=PLACEHOLDER_ACCESS_TOKEN", (req, res) => {
  return req.query.access_token;
});
"#,
        );

        assert_detector(&output, "query_param.read");
        let text = detected_text(&output);
        assert!(!text.contains("PLACEHOLDER_ACCESS_TOKEN"));
        assert!(text.contains(REDACTION));
    }

    fn assert_artifact(output: &DetectionOutput, artifact_type: ArtifactType, name: &str) {
        assert!(
            output.artifacts.iter().any(|artifact| {
                artifact.artifact_type == artifact_type
                    && artifact.display_name.as_deref() == Some(name)
            }),
            "expected {artifact_type:?} named {name} in {:?}",
            output.artifacts
        );
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

    fn detected_text(output: &DetectionOutput) -> String {
        output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.as_str())
            .chain(
                output
                    .artifacts
                    .iter()
                    .filter_map(|artifact| artifact.display_name.as_deref()),
            )
            .collect::<Vec<_>>()
            .join("\n")
    }
}
