use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, EvidenceId, Language, LifecycleEvidence,
    LifecycleStage, SanitizedExcerpt, SourceLocation, TokenBoundaryAttributeState,
    TokenBoundaryAttributes, TokenBoundaryObservation, stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "bearer.token";
const REDACTION: &str = "[REDACTED]";

static QUOTED_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
        .expect("quoted literal regex should compile")
});
static TEMPLATE_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"`(?:\\.|[^`\\])*`"#).expect("template literal regex should compile")
});
static BEARER_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{6,})"#)
        .expect("bearer value regex should compile")
});
static URL_PARAM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)([?&](?:access[_-]?token|service[_-]?token|api[_-]?key|apikey|token)=)([^&#\s"']+)"#,
    )
    .expect("url param regex should compile")
});
static SENSITIVE_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(\b(?:access[_-]?token|bearer[_-]?token|service[_-]?token|api[_-]?key|apikey|client[_-]?token|token|secret)\b\s*[:=]\s*)(["'])([^"']+)(["'])"#,
    )
    .expect("sensitive assignment regex should compile")
});
static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT|KEY)[A-Z0-9_]*\b")
        .expect("placeholder secret regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static LONG_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_+/=-]{32,}\b").expect("long token regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct BearerTokenDetector;

impl Detector for BearerTokenDetector {
    fn id(&self) -> &'static str {
        DETECTOR_ID
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        match input.language {
            Language::JavaScript | Language::TypeScript => detect_javascript_like(input),
            Language::Python => detect_python(input),
            Language::Json | Language::Yaml | Language::Toml => detect_config(input),
            _ => DetectionOutput::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Signal {
    detector_id: &'static str,
    stage: LifecycleStage,
    artifact_type: ArtifactType,
    display_name: String,
    framework_hint: &'static str,
    line: usize,
    column: usize,
    confidence: Confidence,
    dynamic: bool,
    boundary_value: Option<String>,
    excerpt: SanitizedExcerpt,
}

fn detect_javascript_like(input: &DetectorInput<'_>) -> DetectionOutput {
    let Some(tree) = parse_javascript_like(input, input.source) else {
        return DetectionOutput::default();
    };

    let mut signals = Vec::new();
    collect_js_signals(tree.root_node(), input.source, input.path, &mut signals);
    signals_to_output(input, signals)
}

fn detect_python(input: &DetectorInput<'_>) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let mut signals = Vec::new();
    collect_python_signals(tree.root_node(), input.source, input.path, &mut signals);
    signals_to_output(input, signals)
}

fn detect_config(input: &DetectorInput<'_>) -> DetectionOutput {
    if is_sessionscope_fixture_metadata(input.path, input.source) {
        return DetectionOutput::default();
    }

    let mut signals = Vec::new();
    for (index, line) in input.source.lines().enumerate() {
        let normalized = normalize_symbol(line);
        if !is_token_config_line(&normalized) {
            continue;
        }

        let artifact_type = artifact_type_for_context(&normalized);
        let display_name = display_name_for_context(&normalized, artifact_type);
        let stage = if normalized.contains("expires") || normalized.contains("ttl") {
            LifecycleStage::Expire
        } else {
            LifecycleStage::Store
        };
        signals.push(Signal {
            detector_id: if is_public_config_context(&normalized) {
                "bearer.store.public_config"
            } else if has_quoted_sensitive_literal(line, &normalized) {
                "bearer.literal.static"
            } else {
                "bearer.store.config"
            },
            stage,
            artifact_type,
            display_name: display_name.clone(),
            framework_hint: config_framework_hint(input.language),
            line: index + 1,
            column: 1,
            confidence: Confidence::High,
            dynamic: false,
            boundary_value: None,
            excerpt: SanitizedExcerpt(sanitize_excerpt(line)),
        });
        collect_config_boundary_signals(
            line,
            &normalized,
            artifact_type,
            display_name,
            input.language,
            index + 1,
            &mut signals,
        );
    }
    signals_to_output(input, signals)
}

fn collect_js_signals(node: Node<'_>, source: &str, path: &str, signals: &mut Vec<Signal>) {
    match node.kind() {
        "call_expression" => collect_js_call_signal(node, source, path, signals),
        "variable_declarator" | "assignment_expression" | "pair" => {
            collect_assignment_signal(node, source, path, "javascript", signals)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_signals(child, source, path, signals);
    }
}

fn collect_python_signals(node: Node<'_>, source: &str, path: &str, signals: &mut Vec<Signal>) {
    match node.kind() {
        "call" => collect_python_call_signal(node, source, path, signals),
        "assignment" | "keyword_argument" | "pair" => {
            collect_assignment_signal(node, source, path, "python", signals)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_signals(child, source, path, signals);
    }
}

fn collect_js_call_signal(node: Node<'_>, source: &str, path: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let normalized = normalize_symbol_without_literals(&text);
    let raw_normalized = normalize_symbol(&text);
    let has_token_context = URL_PARAM_RE.is_match(&text)
        || contains_token_context(&normalized)
        || (is_browser_storage_call(&raw_normalized)
            && contains_browser_session_context(&raw_normalized))
        || (normalized.contains("headers") && contains_token_context(&raw_normalized));
    if !has_token_context {
        return;
    }

    let context = if contains_token_context(&normalized) {
        normalized.as_str()
    } else {
        raw_normalized.as_str()
    };
    let artifact_type = artifact_type_for_context(context);
    let display_name = display_name_for_context(context, artifact_type);

    if is_jwt_library_call(&normalized) {
        return;
    }

    if is_issue_call(&normalized) {
        signals.push(signal(
            "bearer.issue",
            LifecycleStage::Issue,
            artifact_type,
            display_name.clone(),
            "javascript",
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_store_call(&normalized) {
        let detector_id = if is_browser_storage_call(&normalized) {
            "bearer.store.browser"
        } else if is_public_config_context(context) {
            "bearer.store.public_config"
        } else if is_frontend_exposed_path(path) {
            "bearer.store.frontend_bundle"
        } else {
            "bearer.store"
        };
        signals.push(signal(
            detector_id,
            LifecycleStage::Store,
            artifact_type,
            display_name.clone(),
            js_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_transmit_call(context, &text) {
        let detector_id = if is_inbound_header_read(context) {
            "bearer.read.inbound"
        } else if is_url_query_transmit(context, &text) {
            "bearer.transmit.url_query"
        } else {
            "bearer.transmit"
        };
        signals.push(signal(
            detector_id,
            LifecycleStage::Transmit,
            artifact_type,
            display_name.clone(),
            js_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_validate_call(&normalized) {
        signals.push(signal(
            "bearer.validate",
            LifecycleStage::Validate,
            artifact_type,
            display_name.clone(),
            js_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_scope_context(&normalized) {
        signals.push(signal(
            "bearer.scope",
            if is_issue_call(&normalized) {
                LifecycleStage::Issue
            } else {
                LifecycleStage::Validate
            },
            artifact_type,
            display_name.clone(),
            js_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_expire_call(&normalized) {
        signals.push(signal(
            "bearer.expire",
            LifecycleStage::Expire,
            artifact_type,
            display_name.clone(),
            js_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_rotation_call(&normalized) {
        signals.push(signal(
            "bearer.rotate",
            LifecycleStage::Refresh,
            artifact_type,
            display_name.clone(),
            js_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_revoke_call(&normalized) {
        signals.push(signal(
            "bearer.revoke",
            LifecycleStage::Revoke,
            artifact_type,
            display_name.clone(),
            js_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_dynamic_provider_call(&normalized) {
        signals.push(signal(
            "bearer.dynamic_provider",
            LifecycleStage::Transmit,
            artifact_type,
            display_name.clone(),
            "provider",
            Confidence::Medium,
            true,
            node,
            source,
        ));
    }
    collect_boundary_signals(
        context,
        artifact_type,
        display_name,
        js_framework_hint(&normalized),
        node,
        source,
        signals,
    );
}

fn collect_python_call_signal(node: Node<'_>, source: &str, path: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let normalized = normalize_symbol_without_literals(&text);
    let raw_normalized = normalize_symbol(&text);
    let has_token_context = URL_PARAM_RE.is_match(&text)
        || contains_token_context(&normalized)
        || (is_browser_storage_call(&raw_normalized)
            && contains_browser_session_context(&raw_normalized))
        || (normalized.contains("headers") && contains_token_context(&raw_normalized));
    if !has_token_context {
        return;
    }

    let context = if contains_token_context(&normalized) {
        normalized.as_str()
    } else {
        raw_normalized.as_str()
    };
    let artifact_type = artifact_type_for_context(context);
    let display_name = display_name_for_context(context, artifact_type);

    if is_issue_call(&normalized) {
        signals.push(signal(
            "bearer.issue",
            LifecycleStage::Issue,
            artifact_type,
            display_name.clone(),
            "python",
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_store_call(&normalized) {
        let detector_id = if is_public_config_context(context) {
            "bearer.store.public_config"
        } else if is_frontend_exposed_path(path) {
            "bearer.store.frontend_bundle"
        } else {
            "bearer.store"
        };
        signals.push(signal(
            detector_id,
            LifecycleStage::Store,
            artifact_type,
            display_name.clone(),
            python_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_transmit_call(context, &text) {
        let detector_id = if is_inbound_header_read(context) {
            "bearer.read.inbound"
        } else if is_url_query_transmit(context, &text) {
            "bearer.transmit.url_query"
        } else {
            "bearer.transmit"
        };
        signals.push(signal(
            detector_id,
            LifecycleStage::Transmit,
            artifact_type,
            display_name.clone(),
            python_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_validate_call(&normalized) {
        signals.push(signal(
            "bearer.validate",
            LifecycleStage::Validate,
            artifact_type,
            display_name.clone(),
            python_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_scope_context(&normalized) {
        signals.push(signal(
            "bearer.scope",
            if is_issue_call(&normalized) {
                LifecycleStage::Issue
            } else {
                LifecycleStage::Validate
            },
            artifact_type,
            display_name.clone(),
            python_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_expire_call(&normalized) {
        signals.push(signal(
            "bearer.expire",
            LifecycleStage::Expire,
            artifact_type,
            display_name.clone(),
            python_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_rotation_call(&normalized) {
        signals.push(signal(
            "bearer.rotate",
            LifecycleStage::Refresh,
            artifact_type,
            display_name.clone(),
            python_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_revoke_call(&normalized) {
        signals.push(signal(
            "bearer.revoke",
            LifecycleStage::Revoke,
            artifact_type,
            display_name.clone(),
            python_framework_hint(&normalized),
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    if is_dynamic_provider_call(&normalized) {
        signals.push(signal(
            "bearer.dynamic_provider",
            LifecycleStage::Transmit,
            artifact_type,
            display_name.clone(),
            "provider",
            Confidence::Medium,
            true,
            node,
            source,
        ));
    }
    collect_boundary_signals(
        context,
        artifact_type,
        display_name,
        python_framework_hint(&normalized),
        node,
        source,
        signals,
    );
}

fn collect_assignment_signal(
    node: Node<'_>,
    source: &str,
    path: &str,
    framework_hint: &'static str,
    signals: &mut Vec<Signal>,
) {
    let text = node_text(node, source);
    let normalized = normalize_symbol_without_literals(&text);
    let raw_normalized = normalize_symbol(&text);
    let has_token_context = contains_token_context(&normalized)
        || (is_browser_storage_call(&raw_normalized)
            && contains_browser_session_context(&raw_normalized))
        || (normalized.contains("headers") && contains_token_context(&raw_normalized));
    if !has_token_context || is_jwt_library_call(&normalized) {
        return;
    }

    let context = if contains_token_context(&normalized) {
        normalized.as_str()
    } else {
        raw_normalized.as_str()
    };
    let artifact_type = artifact_type_for_context(context);
    let display_name = display_name_for_context(context, artifact_type);
    let stage = if normalized.contains("expires")
        || normalized.contains("expiresat")
        || normalized.contains("ttl")
    {
        LifecycleStage::Expire
    } else if normalized.contains("header") || normalized.contains("authorization") {
        LifecycleStage::Transmit
    } else {
        LifecycleStage::Store
    };
    let detector_id = if is_public_config_context(context) {
        "bearer.store.public_config"
    } else if is_frontend_exposed_path(path) && stage == LifecycleStage::Store {
        "bearer.store.frontend_bundle"
    } else if has_quoted_sensitive_literal(&text, &normalized) {
        "bearer.literal.static"
    } else if is_inbound_header_read(&normalized) {
        "bearer.read.inbound"
    } else if stage == LifecycleStage::Transmit {
        "bearer.transmit"
    } else {
        "bearer.store.config"
    };

    signals.push(signal(
        detector_id,
        stage,
        artifact_type,
        display_name.clone(),
        framework_hint,
        Confidence::High,
        false,
        node,
        source,
    ));

    if is_scope_context(&normalized) {
        signals.push(signal(
            "bearer.scope",
            if stage == LifecycleStage::Store {
                LifecycleStage::Issue
            } else {
                LifecycleStage::Validate
            },
            artifact_type,
            display_name.clone(),
            framework_hint,
            Confidence::High,
            false,
            node,
            source,
        ));
    }
    collect_boundary_signals(
        context,
        artifact_type,
        display_name,
        framework_hint,
        node,
        source,
        signals,
    );
}

#[allow(clippy::too_many_arguments)]
fn signal(
    detector_id: &'static str,
    stage: LifecycleStage,
    artifact_type: ArtifactType,
    display_name: String,
    framework_hint: &'static str,
    confidence: Confidence,
    dynamic: bool,
    node: Node<'_>,
    source: &str,
) -> Signal {
    let (line, column) = node_line_column(node);
    Signal {
        detector_id,
        stage,
        artifact_type,
        display_name,
        framework_hint,
        line,
        column,
        confidence,
        dynamic,
        boundary_value: None,
        excerpt: SanitizedExcerpt(sanitize_excerpt(&node_text(node, source))),
    }
}

fn boundary_signal(
    detector_id: &'static str,
    boundary_value: Option<String>,
    artifact_type: ArtifactType,
    display_name: String,
    framework_hint: &'static str,
    node: Node<'_>,
    source: &str,
) -> Signal {
    let mut signal = signal(
        detector_id,
        LifecycleStage::Introspect,
        artifact_type,
        display_name,
        framework_hint,
        Confidence::High,
        false,
        node,
        source,
    );
    signal.boundary_value = boundary_value.map(|value| normalize_boundary_value(&value));
    signal
}

fn collect_boundary_signals(
    context: &str,
    artifact_type: ArtifactType,
    display_name: String,
    framework_hint: &'static str,
    node: Node<'_>,
    source: &str,
    signals: &mut Vec<Signal>,
) {
    for (detector_id, value) in boundary_kinds_for_context(context) {
        signals.push(boundary_signal(
            detector_id,
            value,
            artifact_type,
            display_name.clone(),
            framework_hint,
            node,
            source,
        ));
    }
}

fn collect_config_boundary_signals(
    line: &str,
    normalized: &str,
    artifact_type: ArtifactType,
    display_name: String,
    language: Language,
    line_number: usize,
    signals: &mut Vec<Signal>,
) {
    for (detector_id, value) in boundary_kinds_for_context(normalized) {
        signals.push(Signal {
            detector_id,
            stage: LifecycleStage::Introspect,
            artifact_type,
            display_name: display_name.clone(),
            framework_hint: config_framework_hint(language),
            line: line_number,
            column: 1,
            confidence: Confidence::High,
            dynamic: false,
            boundary_value: value.map(|value| normalize_boundary_value(&value)),
            excerpt: SanitizedExcerpt(sanitize_excerpt(line)),
        });
    }
}

fn boundary_kinds_for_context(context: &str) -> Vec<(&'static str, Option<String>)> {
    let mut kinds = Vec::new();
    if context.contains("issuer") || context.contains("iss") {
        kinds.push((
            "bearer.boundary.issuer",
            boundary_value(context, ISSUER_BOUNDARY_TERMS),
        ));
    }
    if context.contains("audience")
        || context.contains("resource")
        || context.contains("aud")
        || context.contains("scope")
        || context.contains("permission")
    {
        kinds.push((
            "bearer.boundary.audience",
            boundary_value(context, AUDIENCE_BOUNDARY_TERMS),
        ));
    }
    if context.contains("service")
        || context.contains("internal")
        || context.contains("server")
        || context.contains("machine")
    {
        kinds.push((
            "bearer.boundary.service",
            boundary_value(context, SERVICE_BOUNDARY_TERMS),
        ));
    }
    if context.contains("prod")
        || context.contains("production")
        || context.contains("staging")
        || context.contains("stage")
        || context.contains("dev")
        || context.contains("development")
        || context.contains("test")
    {
        kinds.push((
            "bearer.boundary.environment",
            boundary_value(context, ENVIRONMENT_BOUNDARY_TERMS),
        ));
    }
    if context.contains("tenant")
        || context.contains("organization")
        || context.contains("workspace")
    {
        kinds.push((
            "bearer.boundary.tenant",
            boundary_value(context, TENANT_BOUNDARY_TERMS),
        ));
    }
    if context.contains("provider")
        || context.contains("auth0")
        || context.contains("okta")
        || context.contains("oauth")
        || context.contains("supabase")
        || context.contains("clerk")
    {
        kinds.push((
            "bearer.boundary.provider",
            boundary_value(context, PROVIDER_BOUNDARY_TERMS),
        ));
    }
    if is_public_config_context(context)
        || is_frontend_context(context)
        || context.contains("backend")
        || context.contains("server")
    {
        kinds.push((
            "bearer.boundary.trust_boundary",
            boundary_value(context, TRUST_BOUNDARY_TERMS),
        ));
    }
    kinds
}

const ISSUER_BOUNDARY_TERMS: &[&str] = &["issuer", "auth0", "okta", "oauth", "provider"];
const AUDIENCE_BOUNDARY_TERMS: &[&str] = &["audience", "resource", "internal", "public", "scope"];
const SERVICE_BOUNDARY_TERMS: &[&str] = &["service", "internal", "backend", "server", "machine"];
const ENVIRONMENT_BOUNDARY_TERMS: &[&str] = &[
    "production",
    "prod",
    "staging",
    "stage",
    "development",
    "dev",
    "test",
];
const TENANT_BOUNDARY_TERMS: &[&str] = &["tenant", "organization", "org", "workspace"];
const PROVIDER_BOUNDARY_TERMS: &[&str] =
    &["provider", "auth0", "okta", "oauth", "supabase", "clerk"];
const TRUST_BOUNDARY_TERMS: &[&str] = &[
    "frontend", "client", "backend", "server", "public", "internal",
];

fn boundary_value(context: &str, terms: &[&str]) -> Option<String> {
    terms
        .iter()
        .find(|term| context.contains(**term))
        .map(|term| (*term).to_string())
}

fn normalize_boundary_value(value: &str) -> String {
    value
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

fn is_frontend_context(context: &str) -> bool {
    context.contains("frontend")
        || context.contains("client")
        || context.contains("browser")
        || context.contains("public")
}

fn boundary_attributes_for_signal(
    signal: &Signal,
    evidence_id: EvidenceId,
) -> Option<TokenBoundaryAttributes> {
    let mut attributes = empty_boundary_attributes();
    let target = match signal.detector_id {
        "bearer.boundary.issuer" => Some(&mut attributes.issuer),
        "bearer.boundary.audience" => Some(&mut attributes.audience),
        "bearer.boundary.service" => Some(&mut attributes.service),
        "bearer.boundary.environment" => Some(&mut attributes.environment),
        "bearer.boundary.tenant" => Some(&mut attributes.tenant),
        "bearer.boundary.provider" => Some(&mut attributes.provider),
        "bearer.scope" => Some(&mut attributes.scope),
        "bearer.boundary.trust_boundary" => Some(&mut attributes.trust_boundary),
        _ => None,
    }?;

    target.state = TokenBoundaryAttributeState::Present;
    target.value = signal.boundary_value.clone();
    target.evidence_ids.push(evidence_id);
    target.confidence = signal.confidence;
    Some(attributes)
}

fn empty_boundary_attributes() -> TokenBoundaryAttributes {
    let observation = TokenBoundaryObservation {
        state: TokenBoundaryAttributeState::Unknown,
        value: None,
        evidence_ids: Vec::new(),
        confidence: Confidence::Low,
    };
    TokenBoundaryAttributes {
        issuer: observation.clone(),
        audience: observation.clone(),
        service: observation.clone(),
        environment: observation.clone(),
        tenant: observation.clone(),
        provider: observation.clone(),
        scope: observation.clone(),
        trust_boundary: observation,
    }
}

fn signals_to_output(input: &DetectorInput<'_>, signals: Vec<Signal>) -> DetectionOutput {
    let mut output = DetectionOutput::default();
    let mut seen = BTreeSet::new();

    for signal in signals {
        let line_part = signal.line.to_string();
        let column_part = signal.column.to_string();
        let artifact_part = artifact_type_part(signal.artifact_type);
        let evidence_id = stable_evidence_id(&[
            DETECTOR_ID,
            signal.detector_id,
            format_stage(signal.stage),
            input.path,
            &line_part,
            &column_part,
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
        push_lifecycle_id(&mut lifecycle_evidence, signal.stage, evidence_id.clone());
        let location = SourceLocation {
            path: input.path.to_string(),
            line: Some(signal.line),
            column: Some(signal.column),
        };

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type: signal.artifact_type,
            display_name: Some(signal.display_name.clone()),
            locations: vec![location.clone()],
            lifecycle_evidence,
            confidence: signal.confidence,
            framework_hints: vec![signal.framework_hint.to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: boundary_attributes_for_signal(&signal, evidence_id.clone()),
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

fn contains_token_context(normalized: &str) -> bool {
    normalized.contains("authorization")
        || normalized.contains("bearer")
        || normalized.contains("session_token")
        || normalized.contains("sessiontoken")
        || normalized.contains("session_id")
        || normalized.contains("sessionid")
        || normalized.contains("apikey")
        || normalized.contains("api_key")
        || normalized.contains("xapikey")
        || normalized.contains("x_api_key")
        || normalized.contains("accesstoken")
        || normalized.contains("access_token")
        || normalized.contains("servicetoken")
        || normalized.contains("service_token")
        || normalized.contains("clienttoken")
        || normalized.contains("client_token")
        || (normalized.contains("token")
            && (normalized.contains("header")
                || normalized.contains("auth")
                || normalized.contains("store")
                || normalized.contains("find")
                || normalized.contains("validate")
                || normalized.contains("verify")
                || normalized.contains("create")
                || normalized.contains("generate")
                || normalized.contains("revoke")
                || normalized.contains("expires")
                || normalized.contains("localstorage")
                || normalized.contains("sessionstorage")
                || normalized.contains("scope")
                || normalized.contains("audience")
                || normalized.contains("permission")
                || normalized.contains("provider")))
        || ((normalized.contains("localstorage") || normalized.contains("sessionstorage"))
            && contains_browser_session_context(normalized))
}

fn contains_browser_session_context(normalized: &str) -> bool {
    normalized.contains("session_token")
        || normalized.contains("sessiontoken")
        || normalized.contains("session_id")
        || normalized.contains("sessionid")
        || normalized.contains("session")
        || normalized.contains("sid")
}

fn is_token_config_line(normalized: &str) -> bool {
    contains_token_context(normalized)
        && (normalized.contains("env")
            || normalized.contains("header")
            || normalized.contains("authorization")
            || normalized.contains("apikey")
            || normalized.contains("api_key")
            || normalized.contains("token"))
}

fn is_public_config_context(normalized: &str) -> bool {
    normalized.contains("next_public")
        || normalized.contains("vite_")
        || normalized.contains("react_app")
        || normalized.contains("public_")
        || normalized.contains("publicruntimeconfig")
        || normalized.contains("runtimeconfig")
        || normalized.contains("clientconfig")
        || normalized.contains("window.__")
}

fn is_frontend_exposed_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.contains("/client/")
        || normalized.contains("/frontend/")
        || normalized.contains("/public/")
        || normalized.contains("/static/")
        || normalized.contains("/browser/")
        || normalized.ends_with(".tsx")
}

fn is_scope_context(normalized: &str) -> bool {
    (normalized.contains("scope")
        || normalized.contains("scopes")
        || normalized.contains("audience")
        || normalized.contains("permission")
        || normalized.contains("permissions"))
        && contains_token_context(normalized)
}

fn is_sessionscope_fixture_metadata(path: &str, source: &str) -> bool {
    (path.ends_with("expected.json")
        || path.ends_with("expected.yaml")
        || path.ends_with("expected.toml"))
        && source.contains("expected_artifacts")
        && source.contains("expected_findings")
}

fn is_issue_call(normalized: &str) -> bool {
    (normalized.contains("create")
        || normalized.contains("generate")
        || normalized.contains("random")
        || normalized.contains("secrets.token")
        || normalized.contains("crypto.random")
        || normalized.contains("nanoid")
        || normalized.contains("uuid"))
        && normalized.contains("token")
}

fn is_store_call(normalized: &str) -> bool {
    normalized.contains("localstorage.setitem")
        || normalized.contains("sessionstorage.setitem")
        || normalized.contains("localstorage.")
        || normalized.contains("sessionstorage.")
        || normalized.contains(".create")
        || normalized.contains(".insert")
        || normalized.contains(".save")
        || normalized.contains(".update")
        || normalized.contains(".set")
        || normalized.contains("os.environ")
        || normalized.contains("process.env")
        || normalized.contains("settings.")
}

fn is_browser_storage_call(normalized: &str) -> bool {
    normalized.contains("localstorage") || normalized.contains("sessionstorage")
}

fn is_transmit_call(normalized: &str, raw: &str) -> bool {
    normalized.contains("authorization")
        || normalized.contains("bearer")
        || normalized.contains("xapikey")
        || normalized.contains("x_api_key")
        || normalized.contains("headers")
        || URL_PARAM_RE.is_match(raw)
        || normalized.contains("params")
}

fn is_url_query_transmit(normalized: &str, raw: &str) -> bool {
    URL_PARAM_RE.is_match(raw)
        || (normalized.contains("params")
            && (normalized.contains("token")
                || normalized.contains("apikey")
                || normalized.contains("api_key")))
}

fn is_validate_call(normalized: &str) -> bool {
    normalized.contains("validate")
        || normalized.contains("verify")
        || normalized.contains("check")
        || normalized.contains("compare_digest")
        || normalized.contains("timingsafeequal")
        || normalized.contains("findunique")
        || normalized.contains("find_unique")
        || normalized.contains("findfirst")
        || normalized.contains("find_first")
        || normalized.contains("findone")
        || normalized.contains("find_one")
}

fn is_expire_call(normalized: &str) -> bool {
    normalized.contains("expires")
        || normalized.contains("expiresat")
        || normalized.contains("expires_at")
        || normalized.contains("ttl")
        || normalized.contains("maxage")
}

fn is_revoke_call(normalized: &str) -> bool {
    normalized.contains("revoke")
        || normalized.contains("disable")
        || normalized.contains("delete")
        || normalized.contains("destroy")
}

fn is_rotation_call(normalized: &str) -> bool {
    (normalized.contains("rotate")
        || normalized.contains("roll")
        || normalized.contains("regenerate")
        || normalized.contains("replace"))
        && (normalized.contains("token")
            || normalized.contains("apikey")
            || normalized.contains("api_key")
            || normalized.contains("key"))
}

fn is_dynamic_provider_call(normalized: &str) -> bool {
    (normalized.contains("provider")
        || normalized.contains("auth0")
        || normalized.contains("oauth")
        || normalized.contains("clientcredentials"))
        && (normalized.contains("token")
            || normalized.contains("apikey")
            || normalized.contains("api_key"))
}

fn is_inbound_header_read(normalized: &str) -> bool {
    (normalized.contains("req.headers")
        || normalized.contains("request.headers")
        || normalized.contains("headers.get"))
        && (normalized.contains("authorization")
            || normalized.contains("xapikey")
            || normalized.contains("x_api_key")
            || normalized.contains("api_key")
            || normalized.contains("apikey"))
}

fn is_jwt_library_call(normalized: &str) -> bool {
    normalized.contains("jwt.sign")
        || normalized.contains("jwt.verify")
        || normalized.contains("jwt.decode")
        || normalized.contains("jsonwebtoken")
        || normalized.contains("jwtverify")
        || normalized.contains("signjwt")
}

fn has_quoted_sensitive_literal(text: &str, normalized: &str) -> bool {
    contains_token_context(normalized)
        && (SENSITIVE_ASSIGNMENT_RE.is_match(text)
            || BEARER_VALUE_RE.is_match(text)
            || PLACEHOLDER_SECRET_RE.is_match(text)
            || LONG_TOKEN_RE.is_match(text))
}

fn artifact_type_for_context(normalized: &str) -> ArtifactType {
    if normalized.contains("apikey")
        || normalized.contains("api_key")
        || normalized.contains("xapikey")
        || normalized.contains("x_api_key")
    {
        ArtifactType::ApiKey
    } else if normalized.contains("service")
        || normalized.contains("machine")
        || normalized.contains("clientcredentials")
        || normalized.contains("client_token")
        || normalized.contains("clienttoken")
        || normalized.contains("internal")
    {
        ArtifactType::ServiceToken
    } else if normalized.contains("bearer")
        || normalized.contains("authorization")
        || normalized.contains("access_token")
        || normalized.contains("accesstoken")
        || normalized.contains("session_token")
        || normalized.contains("sessiontoken")
        || normalized.contains("session_id")
        || normalized.contains("sessionid")
        || ((normalized.contains("localstorage") || normalized.contains("sessionstorage"))
            && (normalized.contains("session") || normalized.contains("sid")))
    {
        ArtifactType::OpaqueBearerToken
    } else {
        ArtifactType::UnknownToken
    }
}

fn display_name_for_context(normalized: &str, artifact_type: ArtifactType) -> String {
    if normalized.contains("xapikey") || normalized.contains("x_api_key") {
        "x_api_key".to_string()
    } else if normalized.contains("api_key") || normalized.contains("apikey") {
        "api_key".to_string()
    } else if normalized.contains("service") {
        "service_token".to_string()
    } else if normalized.contains("authorization") || normalized.contains("bearer") {
        "authorization_bearer".to_string()
    } else if normalized.contains("access_token") || normalized.contains("accesstoken") {
        "access_token".to_string()
    } else if normalized.contains("session_token") || normalized.contains("sessiontoken") {
        "session_token".to_string()
    } else if normalized.contains("session_id") || normalized.contains("sessionid") {
        "session_id".to_string()
    } else if normalized.contains("session") {
        "session".to_string()
    } else if normalized.contains("sid") {
        "sid".to_string()
    } else {
        artifact_type_part(artifact_type).to_string()
    }
}

fn js_framework_hint(normalized: &str) -> &'static str {
    if normalized.contains("cookies") || normalized.contains("next") {
        "nextjs"
    } else if normalized.contains("req.")
        || normalized.contains("res.")
        || normalized.contains("express")
    {
        "express"
    } else if normalized.contains("axios") || normalized.contains("fetch") {
        "javascript-http-client"
    } else {
        "javascript"
    }
}

fn python_framework_hint(normalized: &str) -> &'static str {
    if normalized.contains("request.headers") || normalized.contains("fastapi") {
        "fastapi"
    } else if normalized.contains("django") || normalized.contains("settings.") {
        "django"
    } else if normalized.contains("requests.") || normalized.contains("httpx.") {
        "python-http-client"
    } else {
        "python"
    }
}

fn config_framework_hint(language: Language) -> &'static str {
    match language {
        Language::Json => "json-config",
        Language::Yaml => "yaml-config",
        Language::Toml => "toml-config",
        _ => "config",
    }
}

fn sanitize_excerpt(excerpt: &str) -> String {
    let mut redacted = BEARER_VALUE_RE
        .replace_all(excerpt, format!("${{1}}{REDACTION}"))
        .to_string();
    redacted = URL_PARAM_RE
        .replace_all(&redacted, format!("${{1}}{REDACTION}"))
        .to_string();
    redacted = SENSITIVE_ASSIGNMENT_RE
        .replace_all(&redacted, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    redacted = JWT_RE.replace_all(&redacted, REDACTION).to_string();
    redacted = PLACEHOLDER_SECRET_RE
        .replace_all(&redacted, REDACTION)
        .to_string();
    redacted = LONG_TOKEN_RE
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
            let value = captures.get(0).expect("full capture").as_str();
            if looks_high_entropy(value) {
                REDACTION.to_string()
            } else {
                value.to_string()
            }
        })
        .to_string();
    if should_redact_string_literals(&redacted) {
        redacted = QUOTED_LITERAL_RE
            .replace_all(&redacted, format!("\"{REDACTION}\""))
            .to_string();
    }
    redacted
}

fn should_redact_string_literals(excerpt: &str) -> bool {
    let normalized = normalize_symbol(excerpt);
    normalized.contains("authorization")
        || normalized.contains("bearer")
        || normalized.contains("token")
        || normalized.contains("apikey")
        || normalized.contains("api_key")
        || normalized.contains("secret")
}

fn looks_high_entropy(value: &str) -> bool {
    value.len() >= 32
        && value.chars().any(|ch| ch.is_ascii_alphabetic())
        && (value.chars().any(|ch| ch.is_ascii_digit())
            || value
                .chars()
                .any(|ch| matches!(ch, '_' | '-' | '+' | '/' | '=')))
}

fn push_lifecycle_id(
    lifecycle_evidence: &mut LifecycleEvidence,
    stage: LifecycleStage,
    evidence_id: sessionscope_model::EvidenceId,
) {
    match stage {
        LifecycleStage::Issue => lifecycle_evidence.issue.push(evidence_id),
        LifecycleStage::Store => lifecycle_evidence.store.push(evidence_id),
        LifecycleStage::Transmit => lifecycle_evidence.transmit.push(evidence_id),
        LifecycleStage::Validate => lifecycle_evidence.validate.push(evidence_id),
        LifecycleStage::Refresh => lifecycle_evidence.refresh.push(evidence_id),
        LifecycleStage::Revoke => lifecycle_evidence.revoke.push(evidence_id),
        LifecycleStage::Expire => lifecycle_evidence.expire.push(evidence_id),
        LifecycleStage::Introspect => lifecycle_evidence.introspect.push(evidence_id),
    }
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

fn format_stage(stage: LifecycleStage) -> &'static str {
    match stage {
        LifecycleStage::Issue => "issue",
        LifecycleStage::Store => "store",
        LifecycleStage::Transmit => "transmit",
        LifecycleStage::Validate => "validate",
        LifecycleStage::Refresh => "refresh",
        LifecycleStage::Revoke => "revoke",
        LifecycleStage::Expire => "expire",
        LifecycleStage::Introspect => "introspect",
    }
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

fn normalize_symbol(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/' | '?' | '&'))
        .collect::<String>()
        .to_ascii_lowercase()
}

fn normalize_symbol_without_literals(value: &str) -> String {
    normalize_symbol(&strip_string_literals(value))
}

fn strip_string_literals(value: &str) -> String {
    let without_templates = TEMPLATE_LITERAL_RE.replace_all(value, "``");
    QUOTED_LITERAL_RE
        .replace_all(&without_templates, "\"\"")
        .to_string()
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{ArtifactType, Language, LifecycleStage};

    use super::*;

    fn detect(language: Language, source: &str) -> DetectionOutput {
        detect_at(
            match language {
                Language::Python => "app.py",
                Language::Json => "config.json",
                _ => "app.ts",
            },
            language,
            source,
        )
    }

    fn detect_at(path: &str, language: Language, source: &str) -> DetectionOutput {
        BearerTokenDetector.detect(&DetectorInput {
            path,
            language,
            source,
        })
    }

    #[test]
    fn detects_javascript_bearer_and_api_key_lifecycle() {
        let output = detect(
            Language::TypeScript,
            r#"
const API_KEY = "PLACEHOLDER_API_KEY";
const serviceToken = generateServiceToken(user.id);
await prisma.apiKey.create({ data: { token: serviceToken, expiresAt } });
localStorage.setItem("api_key", API_KEY);
await fetch("https://api.example.test/users", { headers: { Authorization: `Bearer ${serviceToken}`, "X-API-Key": API_KEY } });
const incoming = req.headers.authorization;
await apiKeyStore.findUnique({ where: { token: incoming } });
await revokeServiceToken(serviceToken);
"#,
        );

        assert_artifact(&output, ArtifactType::ApiKey, "api_key");
        assert_artifact(&output, ArtifactType::ServiceToken, "service_token");
        assert_detector(&output, "bearer.literal.static", LifecycleStage::Store);
        assert_detector(&output, "bearer.store.browser", LifecycleStage::Store);
        assert_detector(&output, "bearer.transmit", LifecycleStage::Transmit);
        assert_detector(&output, "bearer.validate", LifecycleStage::Validate);
        assert_detector(&output, "bearer.expire", LifecycleStage::Expire);
        assert_detector(&output, "bearer.revoke", LifecycleStage::Revoke);
        assert!(!detected_text(&output).contains("PLACEHOLDER_API_KEY"));
    }

    #[test]
    fn detects_python_bearer_and_api_key_lifecycle() {
        let output = detect(
            Language::Python,
            r#"
import os, secrets, httpx
API_KEY = "PLACEHOLDER_API_KEY"
service_token = secrets.token_urlsafe(32)
token_store.create({"token": service_token, "expires_at": expires_at})
headers = {"Authorization": f"Bearer {service_token}", "X-API-Key": os.environ["API_KEY"]}
httpx.get("https://api.example.test/users", headers=headers)
incoming = request.headers.get("authorization")
api_key_store.find_one({"token": incoming})
disable_service_token(service_token)
"#,
        );

        assert_artifact(&output, ArtifactType::ApiKey, "api_key");
        assert_artifact(&output, ArtifactType::ServiceToken, "service_token");
        assert_detector(&output, "bearer.literal.static", LifecycleStage::Store);
        assert_detector(&output, "bearer.transmit", LifecycleStage::Transmit);
        assert_detector(&output, "bearer.validate", LifecycleStage::Validate);
        assert_detector(&output, "bearer.revoke", LifecycleStage::Revoke);
        assert!(!detected_text(&output).contains("PLACEHOLDER_API_KEY"));
    }

    #[test]
    fn detects_config_references_without_values() {
        let output = detect(
            Language::Json,
            r#"{ "service_token_env": "SERVICE_TOKEN", "x_api_key_header": "X-API-Key" }"#,
        );

        assert!(output.artifacts.iter().any(|artifact| {
            matches!(
                artifact.artifact_type,
                ArtifactType::ServiceToken | ArtifactType::ApiKey
            )
        }));
        assert!(!detected_text(&output).contains("SERVICE_TOKEN"));
    }

    #[test]
    fn ignores_comments_strings_and_jwt_calls() {
        let output = detect(
            Language::TypeScript,
            r#"
// fetch("/callback?access_token=PLACEHOLDER_TOKEN")
const sample = "Authorization: Bearer PLACEHOLDER_TOKEN";
jwt.verify(token, JWT_SECRET);
const csrfTokenLabel = "not auth storage";
"#,
        );

        assert!(output.artifacts.is_empty(), "{:?}", output.artifacts);
        assert!(output.evidence.is_empty(), "{:?}", output.evidence);
    }

    #[test]
    fn dynamic_provider_calls_are_review_context() {
        let output = detect(
            Language::TypeScript,
            "const client = auth0Provider.clientCredentialsToken({ audience });",
        );

        assert_detector(&output, "bearer.dynamic_provider", LifecycleStage::Transmit);
        assert!(output.evidence.iter().any(|evidence| evidence.dynamic));
    }

    #[test]
    fn public_config_and_frontend_paths_are_tagged() {
        let config_output = detect(
            Language::Json,
            r#"{ "NEXT_PUBLIC_API_KEY": "PLACEHOLDER_API_KEY_DO_NOT_USE" }"#,
        );
        assert_detector(
            &config_output,
            "bearer.store.public_config",
            LifecycleStage::Store,
        );
        assert!(!detected_text(&config_output).contains("PLACEHOLDER_API_KEY_DO_NOT_USE"));

        let frontend_output = detect_at(
            "src/client/app.ts",
            Language::TypeScript,
            r#"const apiKey = process.env.API_KEY;"#,
        );
        assert_detector(
            &frontend_output,
            "bearer.store.frontend_bundle",
            LifecycleStage::Store,
        );
    }

    #[test]
    fn detects_session_like_browser_storage_forms() {
        let output = detect(
            Language::TypeScript,
            r#"
localStorage.setItem("session", sessionValue);
sessionStorage.session_id = sessionId;
localStorage["session_token"] = sessionToken;
"#,
        );

        assert_detector(&output, "bearer.store.browser", LifecycleStage::Store);
        assert_artifact(&output, ArtifactType::OpaqueBearerToken, "session_id");
        assert_artifact(&output, ArtifactType::OpaqueBearerToken, "session_token");
    }

    #[test]
    fn detects_scope_and_rotation_evidence() {
        let output = detect(
            Language::TypeScript,
            r#"
const token = generateServiceToken({ scopes: ["orders:read"] });
requireScope(token, "orders:read");
await rotateServiceToken(token);
"#,
        );

        assert_detector(&output, "bearer.scope", LifecycleStage::Issue);
        assert_detector(&output, "bearer.scope", LifecycleStage::Validate);
        assert_detector(&output, "bearer.rotate", LifecycleStage::Refresh);
    }

    #[test]
    fn detects_boundary_evidence_for_service_environment_provider_and_tenant() {
        let js_output = detect(
            Language::TypeScript,
            r#"
const serviceToken = process.env.PRODUCTION_SERVICE_TOKEN;
await fetch("https://orders.example.invalid", {
  headers: { "X-Service-Token": serviceToken, audience: "orders_api", tenant: tenantId },
});
const providerToken = auth0Provider.clientCredentialsToken({ token: serviceToken });
"#,
        );

        assert_detector(
            &js_output,
            "bearer.boundary.service",
            LifecycleStage::Introspect,
        );
        assert_detector(
            &js_output,
            "bearer.boundary.environment",
            LifecycleStage::Introspect,
        );
        assert_detector(
            &js_output,
            "bearer.boundary.audience",
            LifecycleStage::Introspect,
        );
        assert_detector(
            &js_output,
            "bearer.boundary.tenant",
            LifecycleStage::Introspect,
        );
        assert_detector(
            &js_output,
            "bearer.boundary.provider",
            LifecycleStage::Introspect,
        );
        assert!(js_output.artifacts.iter().any(|artifact| {
            artifact
                .token_boundary_attributes
                .as_ref()
                .is_some_and(|attributes| {
                    !attributes.service.evidence_ids.is_empty()
                        || !attributes.environment.evidence_ids.is_empty()
                        || !attributes.provider.evidence_ids.is_empty()
                })
        }));
    }

    #[test]
    fn detects_config_boundary_evidence() {
        let output = detect(
            Language::Yaml,
            r#"
production_service_token_env: PROD_SERVICE_TOKEN
staging_service_token_env: STAGING_SERVICE_TOKEN
"#,
        );

        assert_detector(
            &output,
            "bearer.boundary.environment",
            LifecycleStage::Introspect,
        );
        assert_detector(
            &output,
            "bearer.boundary.service",
            LifecycleStage::Introspect,
        );
        assert!(!detected_text(&output).contains("PLACEHOLDER"));
    }

    #[test]
    fn ignores_sessionscope_fixture_metadata() {
        let output = detect_at(
            "fixtures/generic-ts/example/expected.json",
            Language::Json,
            r#"{
  "fixture_id": "example",
  "expected_artifacts": ["api_key"],
  "expected_findings": ["bearer_public_runtime_config_exposure"]
}"#,
        );

        assert!(output.artifacts.is_empty(), "{:?}", output.artifacts);
        assert!(output.evidence.is_empty(), "{:?}", output.evidence);
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

    fn assert_detector(output: &DetectionOutput, detector_id: &str, stage: LifecycleStage) {
        assert!(
            output.evidence.iter().any(|evidence| {
                evidence.detector_id == detector_id && evidence.lifecycle_stage == stage
            }),
            "expected {detector_id} at {stage:?} in {:?}",
            output.evidence
        );
    }

    fn detected_text(output: &DetectionOutput) -> String {
        output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.0.as_str())
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
