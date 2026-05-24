use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, Language, LifecycleEvidence, LifecycleStage,
    SanitizedExcerpt, SourceLocation, stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput, providers};

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
static QUOTED_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
        .expect("quoted literal regex should compile")
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

#[derive(Debug, Clone, Copy, Default)]
pub struct RefreshTokenLifecycleDetector;

impl Detector for RefreshTokenLifecycleDetector {
    fn id(&self) -> &'static str {
        "refresh.lifecycle"
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        match input.language {
            Language::JavaScript | Language::TypeScript => detect_refresh_javascript_like(input),
            Language::Python => detect_refresh_python(input),
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
    framework_default: bool,
    scope_hint: Option<String>,
    excerpt: SanitizedExcerpt,
}

#[derive(Debug, Clone)]
struct SignalSpec {
    detector_id: &'static str,
    stage: LifecycleStage,
    artifact_type: ArtifactType,
    display_name: String,
    framework_hint: &'static str,
    confidence: Confidence,
    dynamic: bool,
    framework_default: bool,
}

impl SignalSpec {
    fn new(
        detector_id: &'static str,
        stage: LifecycleStage,
        artifact_type: ArtifactType,
        display_name: impl Into<String>,
        framework_hint: &'static str,
        confidence: Confidence,
        dynamic: bool,
    ) -> Self {
        Self {
            detector_id,
            stage,
            artifact_type,
            display_name: display_name.into(),
            framework_hint,
            confidence,
            dynamic,
            framework_default: false,
        }
    }

    fn revoke(
        detector_id: &'static str,
        artifact_type: ArtifactType,
        display_name: impl Into<String>,
        framework_hint: &'static str,
        confidence: Confidence,
        dynamic: bool,
    ) -> Self {
        Self::new(
            detector_id,
            LifecycleStage::Revoke,
            artifact_type,
            display_name,
            framework_hint,
            confidence,
            dynamic,
        )
    }

    fn framework_default(mut self) -> Self {
        self.framework_default = true;
        self
    }
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

fn detect_refresh_javascript_like(input: &DetectorInput<'_>) -> DetectionOutput {
    let Some(tree) = parse_javascript_like(input, input.source) else {
        return DetectionOutput::default();
    };

    let mut signals = Vec::new();
    collect_refresh_js_signals(tree.root_node(), input.source, &mut signals);
    signals_to_output(input, signals)
}

fn detect_refresh_python(input: &DetectorInput<'_>) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let mut signals = Vec::new();
    collect_refresh_python_signals(tree.root_node(), input.source, &mut signals);
    signals_to_output(input, signals)
}

fn collect_refresh_js_signals(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    match node.kind() {
        "call_expression" => collect_refresh_js_call_signal(node, source, signals),
        "function_declaration" | "method_definition"
            if js_function_name(node, source)
                .as_deref()
                .is_some_and(|name| name.to_ascii_lowercase().contains("refresh")) =>
        {
            signals.push(refresh_signal(
                "refresh.handler",
                LifecycleStage::Refresh,
                node,
                source,
                "javascript",
                Confidence::Medium,
                true,
            ));
        }
        "export_statement" => {
            let text = node_text(node, source);
            let normalized = normalize_symbol(&text);
            if normalized.contains("refresh")
                && (normalized.contains("functionpatch")
                    || normalized.contains("functionpost")
                    || normalized.contains("constpatch")
                    || normalized.contains("constpost"))
            {
                signals.push(refresh_signal(
                    "refresh.handler",
                    LifecycleStage::Refresh,
                    node,
                    source,
                    "nextjs",
                    Confidence::Medium,
                    true,
                ));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_refresh_js_signals(child, source, signals);
    }
}

fn collect_refresh_js_call_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let normalized = normalize_symbol_without_literals(&text);

    if is_js_refresh_route(&text) {
        signals.push(refresh_signal(
            "refresh.handler",
            LifecycleStage::Refresh,
            node,
            source,
            "express",
            Confidence::High,
            false,
        ));
    }

    if is_refresh_cookie_store_call(node, source) || is_refresh_store_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.store",
            LifecycleStage::Store,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
        if has_refresh_expiry_text(&normalized) {
            signals.push(refresh_signal(
                "refresh.expire",
                LifecycleStage::Expire,
                node,
                source,
                refresh_framework_hint(&text),
                Confidence::High,
                false,
            ));
        }
    }

    if is_refresh_issue_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.issue",
            LifecycleStage::Issue,
            node,
            source,
            "javascript",
            Confidence::High,
            false,
        ));
    }

    if is_refresh_validate_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.validate",
            LifecycleStage::Validate,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
    }

    if is_refresh_rotate_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.rotate",
            LifecycleStage::Refresh,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
        if has_old_token_invalidation_text(&normalized) {
            signals.push(refresh_signal(
                "refresh.rotate",
                LifecycleStage::Revoke,
                node,
                source,
                refresh_framework_hint(&text),
                Confidence::High,
                false,
            ));
        }
    } else if is_refresh_revoke_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.revoke",
            LifecycleStage::Revoke,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
    }

    if is_refresh_reuse_detection(&normalized) {
        signals.push(refresh_signal(
            "refresh.reuse_detection",
            LifecycleStage::Validate,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
        if has_family_invalidation_text(&normalized) {
            signals.push(refresh_signal(
                "refresh.reuse_detection",
                LifecycleStage::Revoke,
                node,
                source,
                refresh_framework_hint(&text),
                Confidence::High,
                false,
            ));
        }
    }

    if is_refresh_provider_call(&normalized) {
        let stage = if normalized.contains("revoke")
            || normalized.contains("delete")
            || normalized.contains("logout")
            || normalized.contains("signout")
        {
            LifecycleStage::Revoke
        } else {
            LifecycleStage::Refresh
        };
        signals.push(refresh_signal(
            "refresh.provider",
            stage,
            node,
            source,
            provider_hint_for_context(&normalized),
            Confidence::Medium,
            true,
        ));
    }
}

fn collect_refresh_python_signals(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    if node.kind() == "function_definition" {
        let name = child_by_field(node, "name").map(|name| node_text(name, source));
        let decorators = python_decorator_text(node, source);
        if name
            .as_deref()
            .is_some_and(|name| name.to_ascii_lowercase().contains("refresh"))
            || decorators.to_ascii_lowercase().contains("/refresh")
        {
            signals.push(refresh_signal(
                "refresh.handler",
                LifecycleStage::Refresh,
                node,
                source,
                python_framework_hint(&decorators),
                Confidence::High,
                false,
            ));
        }
    }

    if node.kind() == "call" {
        collect_refresh_python_call_signal(node, source, signals);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_refresh_python_signals(child, source, signals);
    }
}

fn collect_refresh_python_call_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let function = child_by_field(node, "function")
        .map(|function| node_text(function, source))
        .unwrap_or_default();
    let text = node_text(node, source);
    let normalized = normalize_symbol_without_literals(&format!("{function} {text}"));

    if is_refresh_store_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.store",
            LifecycleStage::Store,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
        if has_refresh_expiry_text(&normalized) {
            signals.push(refresh_signal(
                "refresh.expire",
                LifecycleStage::Expire,
                node,
                source,
                refresh_framework_hint(&text),
                Confidence::High,
                false,
            ));
        }
    }

    if is_refresh_issue_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.issue",
            LifecycleStage::Issue,
            node,
            source,
            "python",
            Confidence::High,
            false,
        ));
    }

    if is_refresh_validate_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.validate",
            LifecycleStage::Validate,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
    }

    if is_refresh_rotate_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.rotate",
            LifecycleStage::Refresh,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
        if has_old_token_invalidation_text(&normalized) {
            signals.push(refresh_signal(
                "refresh.rotate",
                LifecycleStage::Revoke,
                node,
                source,
                refresh_framework_hint(&text),
                Confidence::High,
                false,
            ));
        }
    } else if is_refresh_revoke_call(&normalized) {
        signals.push(refresh_signal(
            "refresh.revoke",
            LifecycleStage::Revoke,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
    }

    if is_refresh_reuse_detection(&normalized) {
        signals.push(refresh_signal(
            "refresh.reuse_detection",
            LifecycleStage::Validate,
            node,
            source,
            refresh_framework_hint(&text),
            Confidence::High,
            false,
        ));
        if has_family_invalidation_text(&normalized) {
            signals.push(refresh_signal(
                "refresh.reuse_detection",
                LifecycleStage::Revoke,
                node,
                source,
                refresh_framework_hint(&text),
                Confidence::High,
                false,
            ));
        }
    }

    if is_refresh_provider_call(&normalized) {
        let stage = if normalized.contains("revoke")
            || normalized.contains("delete")
            || normalized.contains("logout")
            || normalized.contains("signout")
        {
            LifecycleStage::Revoke
        } else {
            LifecycleStage::Refresh
        };
        signals.push(refresh_signal(
            "refresh.provider",
            stage,
            node,
            source,
            provider_hint_for_context(&normalized),
            Confidence::Medium,
            true,
        ));
    }
}

fn collect_js_signals(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    match node.kind() {
        "call_expression" => collect_js_call_signal(node, source, signals),
        "assignment_expression" | "augmented_assignment_expression" | "expression_statement" => {
            collect_js_assignment_signal(node, source, signals);
        }
        "function_declaration" | "method_definition"
            if js_function_name(node, source).is_some_and(|name| {
                name == "DELETE" || name.to_ascii_lowercase().contains("logout")
            }) =>
        {
            signals.push(signal(
                SignalSpec::revoke(
                    "logout.handler",
                    ArtifactType::Unknown,
                    "logout",
                    "javascript",
                    Confidence::Medium,
                    true,
                ),
                node,
                source,
            ));
        }
        "function_declaration" | "method_definition" => {
            let name = js_function_name(node, source).unwrap_or_default();
            let normalized = normalize_symbol(&name);
            if is_password_change_handler_context(&normalized) {
                signals.push(signal(
                    SignalSpec::revoke(
                        "password_change.handler",
                        ArtifactType::Unknown,
                        "password_change",
                        "javascript",
                        Confidence::Medium,
                        true,
                    ),
                    node,
                    source,
                ));
            } else if is_auth_handler_context(&normalized) {
                signals.push(session_fixation_signal(
                    "session.auth_transition",
                    LifecycleStage::Issue,
                    node,
                    source,
                    "javascript",
                    Confidence::Medium,
                    true,
                    false,
                ));
            } else if is_privilege_transition_context(&normalized) {
                signals.push(session_fixation_signal(
                    "session.privilege_transition",
                    LifecycleStage::Issue,
                    node,
                    source,
                    "javascript",
                    Confidence::Medium,
                    true,
                    false,
                ));
            }
        }
        "export_statement" => {
            let text = node_text(node, source);
            if text.contains("function DELETE") || text.contains("const DELETE") {
                signals.push(signal(
                    SignalSpec::revoke(
                        "logout.handler",
                        ArtifactType::Unknown,
                        "logout",
                        "nextjs",
                        Confidence::Medium,
                        true,
                    ),
                    node,
                    source,
                ));
            }
            let normalized = normalize_symbol_without_literals(&text);
            if is_password_change_handler_context(&normalized) {
                signals.push(signal(
                    SignalSpec::revoke(
                        "password_change.handler",
                        ArtifactType::Unknown,
                        "password_change",
                        "nextjs",
                        Confidence::Medium,
                        true,
                    ),
                    node,
                    source,
                ));
            } else if is_auth_handler_context(&normalized) {
                signals.push(session_fixation_signal(
                    "session.auth_transition",
                    LifecycleStage::Issue,
                    node,
                    source,
                    "nextjs",
                    Confidence::Medium,
                    true,
                    false,
                ));
            } else if is_privilege_transition_context(&normalized) {
                signals.push(session_fixation_signal(
                    "session.privilege_transition",
                    LifecycleStage::Issue,
                    node,
                    source,
                    "nextjs",
                    Confidence::Medium,
                    true,
                    false,
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
    let normalized = normalize_symbol_without_literals(&text);

    if is_js_provider_session_config_call(&normalized) {
        signals.push(signal(
            SignalSpec::new(
                "session.provider_config",
                LifecycleStage::Store,
                ArtifactType::SessionRecord,
                "session",
                provider_hint_for_context(&normalized),
                Confidence::Medium,
                true,
            ),
            node,
            source,
        ));
    }

    if is_js_session_middleware_call(&normalized) {
        signals.push(signal(
            SignalSpec::new(
                "session.middleware",
                LifecycleStage::Store,
                ArtifactType::SessionRecord,
                "session",
                "express",
                Confidence::Medium,
                true,
            ),
            node,
            source,
        ));
    }

    if is_js_auth_transition_route(&text) {
        signals.push(session_fixation_signal(
            "session.auth_transition",
            LifecycleStage::Issue,
            node,
            source,
            "express",
            Confidence::High,
            false,
            false,
        ));
    }

    if is_js_privilege_transition_route(&text) || is_privilege_transition_call(&normalized) {
        signals.push(session_fixation_signal(
            "session.privilege_transition",
            LifecycleStage::Issue,
            node,
            source,
            js_session_framework_hint(&text),
            if is_js_privilege_transition_route(&text) {
                Confidence::High
            } else {
                Confidence::Medium
            },
            !is_js_privilege_transition_route(&text),
            false,
        ));
    }

    if is_js_session_regenerate_call(&normalized) {
        signals.push(session_fixation_signal(
            "session.regenerate",
            LifecycleStage::Refresh,
            node,
            source,
            js_session_framework_hint(&text),
            Confidence::High,
            false,
            false,
        ));
    }

    if is_js_session_reissue_context(node, source) {
        signals.push(session_fixation_signal(
            "session.reissue",
            LifecycleStage::Refresh,
            node,
            source,
            "cookie-session",
            Confidence::Medium,
            true,
            false,
        ));
    }

    if is_js_session_cookie_store_call(node, source) && is_auth_or_privilege_ancestor(node, source)
    {
        signals.push(session_fixation_signal(
            "session.store_after_auth",
            LifecycleStage::Store,
            node,
            source,
            js_session_framework_hint(&text),
            Confidence::High,
            false,
            false,
        ));
    }

    if is_js_logout_route(&text) {
        signals.push(signal(
            SignalSpec::revoke(
                "logout.handler",
                ArtifactType::Unknown,
                "logout",
                "express",
                Confidence::High,
                false,
            ),
            node,
            source,
        ));
    }

    if is_js_clear_cookie_call(node, source) {
        let name = first_call_string_argument(node, source)
            .and_then(|name| safe_static_cookie_name(&name))
            .unwrap_or_else(|| "cookie".to_string());
        signals.push(signal(
            SignalSpec::revoke(
                "logout.cookie_clear",
                cookie_artifact_type(&name),
                name.clone(),
                js_cookie_clear_framework(&text),
                if name == "cookie" {
                    Confidence::Medium
                } else {
                    Confidence::High
                },
                name == "cookie",
            ),
            node,
            source,
        ));
        return;
    }

    if is_js_session_destroy_call(&normalized) {
        signals.push(signal(
            SignalSpec::revoke(
                "logout.session_destroy",
                ArtifactType::SessionRecord,
                "session",
                "javascript",
                Confidence::High,
                false,
            ),
            node,
            source,
        ));
        return;
    }

    if is_global_password_change_revocation_call(&normalized) {
        signals.push(signal(
            SignalSpec::revoke(
                "password_change.global_revoke",
                ArtifactType::SessionRecord,
                "session",
                "javascript",
                Confidence::High,
                false,
            ),
            node,
            source,
        ));
    }

    if is_js_provider_revoke_call(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            SignalSpec::revoke(
                "logout.provider_revoke",
                token_artifact_type(&display_name),
                display_name,
                provider_hint_for_context(&normalized),
                Confidence::Medium,
                true,
            ),
            node,
            source,
        ));
        return;
    }

    if is_token_revoke_call(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            SignalSpec::revoke(
                "logout.token_revoke",
                token_artifact_type(&display_name),
                display_name,
                "javascript",
                Confidence::Medium,
                true,
            ),
            node,
            source,
        ));
    }
}

fn collect_js_assignment_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let normalized = normalize_symbol(&text);
    if is_js_session_mutation(&normalized) && is_auth_or_privilege_ancestor(node, source) {
        signals.push(session_fixation_signal(
            "session.store_after_auth",
            LifecycleStage::Store,
            node,
            source,
            js_session_framework_hint(&ancestor_context_text(node, source)),
            Confidence::High,
            false,
            false,
        ));
    }
}

fn collect_python_signals(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    if node.kind() == "function_definition" {
        let name = child_by_field(node, "name").map(|name| node_text(name, source));
        let decorators = python_decorator_text(node, source);
        let normalized_context = normalize_symbol(&format!(
            "{} {}",
            name.clone().unwrap_or_default(),
            decorators
        ));
        if name
            .as_deref()
            .is_some_and(|name| name.to_ascii_lowercase().contains("logout"))
            || decorators.to_ascii_lowercase().contains("/logout")
        {
            signals.push(signal(
                SignalSpec::revoke(
                    "logout.handler",
                    ArtifactType::Unknown,
                    "logout",
                    python_framework_hint(&decorators),
                    Confidence::High,
                    false,
                ),
                node,
                source,
            ));
        } else if is_password_change_handler_context(&normalized_context) {
            signals.push(signal(
                SignalSpec::revoke(
                    "password_change.handler",
                    ArtifactType::Unknown,
                    "password_change",
                    python_framework_hint(&decorators),
                    Confidence::High,
                    false,
                ),
                node,
                source,
            ));
        } else if is_auth_handler_context(&normalized_context) {
            signals.push(session_fixation_signal(
                "session.auth_transition",
                LifecycleStage::Issue,
                node,
                source,
                python_framework_hint(&decorators),
                Confidence::High,
                false,
                false,
            ));
        } else if is_privilege_transition_context(&normalized_context) {
            signals.push(session_fixation_signal(
                "session.privilege_transition",
                LifecycleStage::Issue,
                node,
                source,
                python_framework_hint(&decorators),
                Confidence::High,
                false,
                false,
            ));
        }
    }

    if node.kind() == "call" {
        collect_python_call_signal(node, source, signals);
    }

    if node.kind() == "assignment"
        || node.kind() == "augmented_assignment"
        || node.kind() == "expression_statement"
    {
        collect_python_assignment_signal(node, source, signals);
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
    let normalized = normalize_symbol_without_literals(&format!("{function} {text}"));

    if is_python_fastapi_security_call(&function, &normalized) {
        signals.push(signal(
            SignalSpec::new(
                "fastapi.security_dependency",
                LifecycleStage::Validate,
                ArtifactType::Unknown,
                "security_dependency",
                "fastapi",
                Confidence::Medium,
                true,
            ),
            node,
            source,
        ));
    }

    if is_python_django_login_call(&function, &normalized) {
        signals.push(session_fixation_signal(
            "session.auth_transition",
            LifecycleStage::Issue,
            node,
            source,
            "django",
            Confidence::High,
            false,
            false,
        ));
        signals.push(session_fixation_signal(
            "session.framework_default_regenerate",
            LifecycleStage::Refresh,
            node,
            source,
            "django",
            Confidence::High,
            false,
            true,
        ));
        return;
    }

    if is_python_session_cycle_key_call(&normalized) {
        signals.push(session_fixation_signal(
            "session.regenerate",
            LifecycleStage::Refresh,
            node,
            source,
            "django",
            Confidence::High,
            false,
            false,
        ));
    }

    if is_python_session_reissue_context(node, source) {
        signals.push(session_fixation_signal(
            "session.reissue",
            LifecycleStage::Refresh,
            node,
            source,
            python_framework_hint(&ancestor_context_text(node, source)),
            Confidence::Medium,
            true,
            false,
        ));
    }

    if is_python_session_cookie_store_call(&function, &normalized)
        && is_auth_or_privilege_ancestor(node, source)
    {
        signals.push(session_fixation_signal(
            "session.store_after_auth",
            LifecycleStage::Store,
            node,
            source,
            python_framework_hint(&ancestor_context_text(node, source)),
            Confidence::High,
            false,
            false,
        ));
    }

    if function.ends_with(".delete_cookie") || function == "delete_cookie" {
        let name = first_call_string_argument(node, source)
            .and_then(|name| safe_static_cookie_name(&name))
            .unwrap_or_else(|| "cookie".to_string());
        signals.push(signal(
            SignalSpec::revoke(
                "logout.cookie_clear",
                cookie_artifact_type(&name),
                name.clone(),
                python_cookie_clear_framework(node),
                if name == "cookie" {
                    Confidence::Medium
                } else {
                    Confidence::High
                },
                name == "cookie",
            ),
            node,
            source,
        ));
        return;
    }

    if function == "logout" || function.ends_with(".logout") || normalized.contains("authlogout") {
        signals.push(signal(
            SignalSpec::revoke(
                "logout.session_destroy",
                ArtifactType::SessionRecord,
                "session",
                "django",
                Confidence::High,
                false,
            ),
            node,
            source,
        ));
        return;
    }

    if is_python_session_destroy_call(&normalized) {
        signals.push(signal(
            SignalSpec::revoke(
                "logout.session_destroy",
                ArtifactType::SessionRecord,
                "session",
                python_framework_hint(&text),
                Confidence::High,
                false,
            ),
            node,
            source,
        ));
        return;
    }

    if is_global_password_change_revocation_call(&normalized) {
        signals.push(signal(
            SignalSpec::revoke(
                "password_change.global_revoke",
                ArtifactType::SessionRecord,
                "session",
                python_framework_hint(&text),
                Confidence::High,
                false,
            ),
            node,
            source,
        ));
    }

    if is_provider_revoke_text(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            SignalSpec::revoke(
                "logout.provider_revoke",
                token_artifact_type(&display_name),
                display_name,
                provider_hint_for_context(&normalized),
                Confidence::Medium,
                true,
            ),
            node,
            source,
        ));
        return;
    }

    if is_token_revoke_call(&normalized) {
        let display_name = token_display_name(&normalized);
        signals.push(signal(
            SignalSpec::revoke(
                "logout.token_revoke",
                token_artifact_type(&display_name),
                display_name,
                "python",
                Confidence::Medium,
                true,
            ),
            node,
            source,
        ));
    }
}

fn collect_python_assignment_signal(node: Node<'_>, source: &str, signals: &mut Vec<Signal>) {
    let text = node_text(node, source);
    let normalized = normalize_symbol(&text);
    if is_python_session_mutation(&normalized) && is_auth_or_privilege_ancestor(node, source) {
        signals.push(session_fixation_signal(
            "session.store_after_auth",
            LifecycleStage::Store,
            node,
            source,
            python_framework_hint(&ancestor_context_text(node, source)),
            Confidence::High,
            false,
            false,
        ));
    }
}

fn signals_to_output(input: &DetectorInput<'_>, signals: Vec<Signal>) -> DetectionOutput {
    let mut output = DetectionOutput::default();
    let mut seen = BTreeSet::new();

    for signal in signals {
        let key = (
            signal.detector_id,
            signal.stage,
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
            format_stage(signal.stage),
            input.path,
            &signal.line.to_string(),
            &signal.column.to_string(),
            &signal.display_name,
        ]);

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type,
            display_name: Some(signal.display_name.clone()),
            locations: vec![location.clone()],
            lifecycle_evidence: lifecycle_evidence_for_stage(signal.stage, evidence_id.clone()),
            confidence: signal.confidence,
            framework_hints: framework_hints_for_signal(&signal),
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
            framework_default: signal.framework_default,
        });
    }

    output
}

fn signal(spec: SignalSpec, node: Node<'_>, source: &str) -> Signal {
    Signal {
        detector_id: spec.detector_id,
        stage: spec.stage,
        artifact_type: spec.artifact_type,
        display_name: normalize_display_name(&spec.display_name),
        framework_hint: spec.framework_hint,
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
        confidence: spec.confidence,
        dynamic: spec.dynamic,
        framework_default: spec.framework_default,
        scope_hint: None,
        excerpt: SanitizedExcerpt::from_sanitized(sanitize_excerpt(&node_text(node, source))),
    }
}

fn framework_hints_for_signal(signal: &Signal) -> Vec<String> {
    let mut hints = vec![signal.framework_hint.to_string()];
    if let Some(scope_hint) = &signal.scope_hint {
        hints.push(scope_hint.clone());
    }
    hints
}

fn handler_scope_hint(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = Some(node);
    let mut depth = 0usize;
    let mut function_scope = None;
    while let Some(candidate) = current {
        let normalized = normalize_symbol(&node_text(candidate, source));
        if candidate.kind() == "call_expression"
            && (is_js_route_call(&normalized)
                || is_auth_transition_context(&normalized)
                || is_privilege_transition_context(&normalized))
        {
            return Some(format!("scope:{}", candidate.start_byte()));
        }
        if matches!(
            candidate.kind(),
            "function_declaration"
                | "function"
                | "arrow_function"
                | "method_definition"
                | "function_definition"
        ) {
            function_scope.get_or_insert_with(|| format!("scope:{}", candidate.start_byte()));
        }
        current = candidate.parent();
        depth += 1;
        if depth > 16 {
            break;
        }
    }
    function_scope
}

#[allow(clippy::too_many_arguments)]
fn session_fixation_signal(
    detector_id: &'static str,
    stage: LifecycleStage,
    node: Node<'_>,
    source: &str,
    framework_hint: &'static str,
    confidence: Confidence,
    dynamic: bool,
    framework_default: bool,
) -> Signal {
    let spec = SignalSpec::new(
        detector_id,
        stage,
        ArtifactType::SessionRecord,
        "session",
        framework_hint,
        confidence,
        dynamic,
    );
    let spec = if framework_default {
        spec.framework_default()
    } else {
        spec
    };
    let mut signal = signal(spec, node, source);
    signal.scope_hint = handler_scope_hint(node, source);
    signal
}

fn refresh_signal(
    detector_id: &'static str,
    stage: LifecycleStage,
    node: Node<'_>,
    source: &str,
    framework_hint: &'static str,
    confidence: Confidence,
    dynamic: bool,
) -> Signal {
    let normalized = normalize_symbol_without_literals(&node_text(node, source));
    signal(
        SignalSpec::new(
            detector_id,
            stage,
            refresh_artifact_type(&normalized),
            "refresh_token",
            framework_hint,
            confidence,
            dynamic,
        ),
        node,
        source,
    )
}

fn lifecycle_evidence_for_stage(
    stage: LifecycleStage,
    evidence_id: sessionscope_model::EvidenceId,
) -> LifecycleEvidence {
    let mut lifecycle_evidence = LifecycleEvidence::default();
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
    lifecycle_evidence
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

fn is_js_auth_transition_route(text: &str) -> bool {
    let normalized = normalize_symbol(text);
    is_js_route_call(&normalized)
        && is_auth_transition_context(&normalized)
        && !is_logout_context(&normalized)
}

fn is_js_privilege_transition_route(text: &str) -> bool {
    let normalized = normalize_symbol(text);
    is_js_route_call(&normalized)
        && is_privilege_transition_context(&normalized)
        && !is_logout_context(&normalized)
}

fn is_js_route_call(normalized: &str) -> bool {
    normalized.contains("app.get")
        || normalized.contains("app.post")
        || normalized.contains("app.put")
        || normalized.contains("app.patch")
        || normalized.contains("router.get")
        || normalized.contains("router.post")
        || normalized.contains("router.put")
        || normalized.contains("router.patch")
}

fn is_auth_transition_context(normalized: &str) -> bool {
    !is_logout_context(normalized)
        && (normalized.contains("login")
            || normalized.contains("signin")
            || normalized.contains("sign_in")
            || normalized.contains("authcallback")
            || normalized.contains("auth/callback")
            || normalized.contains("authenticate")
            || normalized.contains("authentication")
            || normalized.contains("password_verify")
            || normalized.contains("passwordverify"))
}

fn is_auth_handler_context(normalized: &str) -> bool {
    !is_logout_context(normalized)
        && (normalized.contains("login")
            || normalized.contains("signin")
            || normalized.contains("sign_in")
            || normalized.contains("authcallback")
            || normalized.contains("auth/callback")
            || normalized.contains("password_verify")
            || normalized.contains("passwordverify"))
}

fn is_privilege_transition_context(normalized: &str) -> bool {
    !is_logout_context(normalized)
        && (normalized.contains("promote")
            || normalized.contains("elevate")
            || normalized.contains("privilege")
            || normalized.contains("permission")
            || normalized.contains("impersonat")
            || normalized.contains("sudo")
            || normalized.contains("makeadmin")
            || normalized.contains("make_admin")
            || normalized.contains("roleadmin")
            || normalized.contains("role/admin")
            || normalized.contains("role_admin")
            || normalized.contains("admin/promote")
            || normalized.contains("grantrole")
            || normalized.contains("grant_role"))
}

fn is_logout_context(normalized: &str) -> bool {
    normalized.contains("logout")
        || normalized.contains("signout")
        || normalized.contains("sign_out")
}

fn is_privilege_transition_call(normalized: &str) -> bool {
    is_privilege_transition_context(normalized)
        && (normalized.contains("set")
            || normalized.contains("update")
            || normalized.contains("grant")
            || normalized.contains("assign")
            || normalized.contains("promote")
            || normalized.contains("impersonat"))
}

fn is_js_session_regenerate_call(normalized: &str) -> bool {
    normalized.contains("session.regenerate")
        || normalized.contains("req.session.regenerate")
        || normalized.contains("request.session.regenerate")
        || normalized.contains("regeneratesession")
        || normalized.contains("rotate_session")
        || normalized.contains("rotatesession")
        || normalized.contains("cyclesession")
}

fn is_js_session_mutation(normalized: &str) -> bool {
    (normalized.contains("req.session")
        || normalized.contains("request.session")
        || normalized.contains("ctx.session")
        || normalized.contains("session.user")
        || normalized.contains("session.userid")
        || normalized.contains("session.user_id")
        || normalized.contains("session.role"))
        && (normalized.contains("user")
            || normalized.contains("account")
            || normalized.contains("role")
            || normalized.contains("admin")
            || normalized.contains("auth")
            || normalized.contains("impersonat"))
}

fn is_js_session_cookie_store_call(node: Node<'_>, source: &str) -> bool {
    let function = child_by_field(node, "function")
        .map(|function| node_text(function, source))
        .unwrap_or_default();
    let normalized = normalize_symbol_without_literals(&node_text(node, source));
    (function.ends_with(".cookie")
        || function.ends_with(".set")
        || function.ends_with(".setCookie")
        || function.ends_with(".set_cookie"))
        && (normalized.contains("session") || normalized.contains("connect.sid"))
}

fn is_js_session_reissue_context(node: Node<'_>, source: &str) -> bool {
    let context = normalize_symbol(&ancestor_context_text(node, source));
    is_auth_transition_context(&context)
        && (context.contains("clearcookie")
            || context.contains("cookies.delete")
            || context.contains("sessionnull")
            || context.contains("req.sessionnull"))
        && (context.contains(".cookie")
            || context.contains("cookies.set")
            || context.contains("setcookie"))
        && context.contains("session")
}

fn is_auth_or_privilege_ancestor(node: Node<'_>, source: &str) -> bool {
    let mut current = node.parent();
    let mut depth = 0;
    while let Some(candidate) = current {
        let context = normalize_symbol(&node_text(candidate, source));
        if is_auth_transition_context(&context) || is_privilege_transition_context(&context) {
            return true;
        }
        current = candidate.parent();
        depth += 1;
        if depth > 16 {
            break;
        }
    }
    false
}

fn ancestor_context_text(node: Node<'_>, source: &str) -> String {
    let mut current = node.parent();
    let mut depth = 0;
    while let Some(candidate) = current {
        if matches!(
            candidate.kind(),
            "call_expression"
                | "function_declaration"
                | "function"
                | "arrow_function"
                | "method_definition"
                | "export_statement"
                | "function_definition"
        ) {
            let text = node_text(candidate, source);
            if text.len() <= 12_000 {
                return text;
            }
            return text.chars().take(12_000).collect();
        }
        current = candidate.parent();
        depth += 1;
        if depth > 16 {
            break;
        }
    }
    node_text(node, source)
}

fn is_js_refresh_route(text: &str) -> bool {
    let normalized = normalize_symbol(text);
    (normalized.contains("app.post")
        || normalized.contains("router.post")
        || normalized.contains("app.patch")
        || normalized.contains("router.patch"))
        && normalized.contains("refresh")
}

fn is_refresh_cookie_store_call(node: Node<'_>, source: &str) -> bool {
    let function = child_by_field(node, "function")
        .map(|function| node_text(function, source))
        .unwrap_or_default();
    let text = strip_string_literals(&node_text(node, source)).to_ascii_lowercase();
    (function.ends_with(".cookie")
        || function.ends_with(".set")
        || function.ends_with(".set_cookie")
        || function == "set_cookie")
        && text.contains("refresh")
}

fn is_js_clear_cookie_call(node: Node<'_>, source: &str) -> bool {
    let function = child_by_field(node, "function")
        .map(|function| node_text(function, source))
        .unwrap_or_default();
    function.ends_with(".clearCookie")
        || function.ends_with(".clear_cookie")
        || function == "clearCookie"
        || (function.ends_with(".delete")
            && (node_text(node, source).contains("cookies()")
                || function.contains(".cookies.delete")))
}

fn js_cookie_clear_framework(text: &str) -> &'static str {
    if text.contains("cookies()") || text.contains(".cookies.delete") {
        "nextjs"
    } else {
        "express"
    }
}

fn is_js_provider_session_config_call(normalized: &str) -> bool {
    contains_provider_context(normalized)
        && (normalized.contains("nextauth")
            || normalized.contains("auth")
            || normalized.contains("session")
            || normalized.contains("passport.authenticate"))
}

fn is_js_session_middleware_call(normalized: &str) -> bool {
    normalized.contains("expresssession")
        || normalized.contains("cookiesession")
        || normalized.contains("appusecookiesession")
        || normalized.contains("routerusecookiesession")
        || ((normalized.contains("appusesession") || normalized.contains("routerusesession"))
            && (normalized.contains("secret")
                || normalized.contains("cookie")
                || normalized.contains("resave")
                || normalized.contains("saveuninitialized")))
        || (normalized.starts_with("session") && normalized.contains("secret"))
        || (normalized.starts_with("cookiesession") && normalized.contains("secret"))
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

fn is_password_change_handler_context(normalized: &str) -> bool {
    (normalized.contains("passwordchange")
        || normalized.contains("password_change")
        || normalized.contains("change_password")
        || normalized.contains("changepassword")
        || normalized.contains("updatepassword")
        || normalized.contains("update_password")
        || normalized.contains("password_update")
        || normalized.contains("passwordupdate"))
        && !normalized.contains("validate")
        && !normalized.contains("validator")
        && !normalized.contains("verify")
        && !normalized.contains("check")
        && !normalized.contains("strength")
}

fn is_global_password_change_revocation_call(normalized: &str) -> bool {
    (normalized.contains("revokeallsessions")
        || normalized.contains("revoke_all_sessions")
        || normalized.contains("invalidateallsessions")
        || normalized.contains("invalidate_all_sessions")
        || normalized.contains("bump token version")
        || normalized.contains("bumptokenversion")
        || normalized.contains("bump_token_version")
        || normalized.contains("tokenversion")
        || normalized.contains("token_version")
        || normalized.contains("cycle_key")
        || normalized.contains("cyclekey"))
        || (normalized.contains("refresh")
            && (normalized.contains("user")
                || normalized.contains("family")
                || normalized.contains("allsessions")
                || normalized.contains("all_sessions"))
            && (normalized.contains("revoke")
                || normalized.contains("delete")
                || normalized.contains("invalidate")
                || normalized.contains("destroy")))
}

fn is_js_provider_revoke_call(normalized: &str) -> bool {
    is_provider_revoke_text(normalized)
}

fn is_provider_revoke_text(normalized: &str) -> bool {
    (contains_provider_context(normalized)
        && (normalized.contains("revoke")
            || normalized.contains("logout")
            || normalized.contains("signout")
            || normalized.contains("sign_out")))
        || normalized.contains("supabase.auth.signout")
        || normalized.contains("clerk.sessions.revoke")
        || normalized.contains("identityprovider.revoke")
}

fn is_refresh_provider_call(normalized: &str) -> bool {
    contains_provider_context(normalized)
        && (normalized.contains("refresh")
            || normalized.contains("rotate")
            || normalized.contains("revoke")
            || normalized.contains("signout")
            || normalized.contains("session")
            || normalized.contains("callback"))
}

fn contains_provider_context(normalized: &str) -> bool {
    normalized.contains("provider")
        || normalized.contains("nextauth")
        || normalized.contains("nextauthoptions")
        || normalized.contains("authjs")
        || normalized.contains("auth.js")
        || normalized.contains("passport")
        || normalized.contains("openidclient")
        || normalized.contains("openid")
        || normalized.contains("oidc")
        || normalized.contains("oauth")
        || normalized.contains("auth0")
        || normalized.contains("okta")
        || normalized.contains("cognito")
        || normalized.contains("azuread")
        || normalized.contains("azure_ad")
        || normalized.contains("firebase")
        || normalized.contains("supabase")
        || normalized.contains("clerk")
}

fn provider_hint_for_context(normalized: &str) -> &'static str {
    if normalized.contains("nextauth") {
        providers::NEXTAUTH
    } else if normalized.contains("authjs") || normalized.contains("auth.js") {
        providers::AUTHJS
    } else if normalized.contains("passport") {
        providers::PASSPORT
    } else if normalized.contains("openid") || normalized.contains("oidc") {
        providers::OIDC
    } else if normalized.contains("auth0") {
        providers::AUTH0
    } else if normalized.contains("okta") {
        providers::OKTA
    } else if normalized.contains("cognito") {
        providers::COGNITO
    } else if normalized.contains("azuread") || normalized.contains("azure_ad") {
        providers::AZURE_AD
    } else if normalized.contains("firebase") {
        providers::FIREBASE
    } else if normalized.contains("supabase") {
        providers::SUPABASE
    } else if normalized.contains("clerk") {
        providers::CLERK
    } else if normalized.contains("oauth") {
        providers::OAUTH
    } else {
        providers::PROVIDER
    }
}

fn is_refresh_issue_call(normalized: &str) -> bool {
    normalized.contains("refresh")
        && (normalized.contains("issuerefresh")
            || normalized.contains("createrefresh")
            || normalized.contains("generaterefresh")
            || normalized.contains("newrefreshtoken")
            || normalized.contains("signrefresh")
            || normalized.contains("signjwt")
            || normalized.contains("jwt.encode")
            || normalized.contains("randombytes")
            || normalized.contains("randomuuid")
            || normalized.contains("token_urlsafe"))
}

fn is_refresh_store_call(normalized: &str) -> bool {
    normalized.contains("refresh")
        && (normalized.contains(".create")
            || normalized.contains(".insert")
            || normalized.contains(".save")
            || normalized.contains(".set")
            || normalized.contains(".update")
            || normalized.contains("storerefresh")
            || normalized.contains("store_refresh")
            || normalized.contains("persist")
            || normalized.contains("set_cookie")
            || normalized.contains("cookies.set"))
}

fn is_refresh_validate_call(normalized: &str) -> bool {
    normalized.contains("refresh")
        && (normalized.contains(".find")
            || normalized.contains("findunique")
            || normalized.contains("findfirst")
            || normalized.contains("findone")
            || normalized.contains("lookup")
            || normalized.contains("compare")
            || normalized.contains("verify")
            || normalized.contains("jwtverify")
            || normalized.contains("jwt.decode")
            || normalized.contains("cookies.get")
            || normalized.contains("request.cookies")
            || normalized.contains("request.body")
            || normalized.contains("revoked")
            || normalized.contains("used")
            || normalized.contains("expires"))
}

fn is_refresh_rotate_call(normalized: &str) -> bool {
    normalized.contains("refresh")
        && (normalized.contains("rotate")
            || normalized.contains("rotation")
            || normalized.contains("markused")
            || normalized.contains("mark_refresh_token_used")
            || normalized.contains("usedat")
            || normalized.contains("revokedat")
            || normalized.contains("replace"))
}

fn is_refresh_revoke_call(normalized: &str) -> bool {
    normalized.contains("refresh")
        && (normalized.contains("revoke")
            || normalized.contains("invalidate")
            || normalized.contains("delete")
            || normalized.contains("destro")
            || normalized.contains("denylist")
            || normalized.contains("blacklist")
            || normalized.contains("revokedat")
            || normalized.contains("passwordchange")
            || normalized.contains("password_change"))
}

fn is_refresh_reuse_detection(normalized: &str) -> bool {
    normalized.contains("refresh")
        && (normalized.contains("reuse")
            || normalized.contains("reused")
            || normalized.contains("tokenfamily")
            || normalized.contains("token_family")
            || normalized.contains("familyid")
            || normalized.contains("family_id"))
}

fn has_old_token_invalidation_text(normalized: &str) -> bool {
    normalized.contains("revoke")
        || normalized.contains("invalidate")
        || normalized.contains("delete")
        || normalized.contains("denylist")
        || normalized.contains("blacklist")
        || normalized.contains("markused")
        || normalized.contains("mark_refresh_token_used")
        || normalized.contains("usedat")
        || normalized.contains("revokedat")
}

fn has_family_invalidation_text(normalized: &str) -> bool {
    has_old_token_invalidation_text(normalized)
        && (normalized.contains("family")
            || normalized.contains("session")
            || normalized.contains("user"))
}

fn has_refresh_expiry_text(normalized: &str) -> bool {
    normalized.contains("expires")
        || normalized.contains("expiresat")
        || normalized.contains("expires_at")
        || normalized.contains("maxage")
        || normalized.contains("max_age")
        || normalized.contains("ttl")
}

fn refresh_artifact_type(normalized: &str) -> ArtifactType {
    if normalized.contains("jwt")
        || normalized.contains("signjwt")
        || normalized.contains("jwt.encode")
        || normalized.contains("jwtverify")
    {
        ArtifactType::RefreshJwt
    } else {
        ArtifactType::Unknown
    }
}

fn refresh_framework_hint(text: &str) -> &'static str {
    let normalized = text.to_ascii_lowercase();
    if normalized.contains("cookies()") {
        "nextjs"
    } else if normalized.contains("@app.") || normalized.contains("@router.") {
        "fastapi"
    } else if normalized.contains("django") {
        "django"
    } else if normalized.contains("provider")
        || normalized.contains("auth0")
        || normalized.contains("okta")
        || normalized.contains("oauth")
        || normalized.contains("supabase")
        || normalized.contains("clerk")
    {
        "provider"
    } else if normalized.contains("app.") || normalized.contains("router.") {
        "express"
    } else if contains_provider_context(&normalized) {
        provider_hint_for_context(&normalized)
    } else {
        "refresh"
    }
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

fn js_session_framework_hint(text: &str) -> &'static str {
    let normalized = text.to_ascii_lowercase();
    if normalized.contains("cookie-session") || normalized.contains("clearcookie") {
        "cookie-session"
    } else if normalized.contains("cookies()") || normalized.contains("nexturl") {
        "nextjs"
    } else if normalized.contains("app.") || normalized.contains("router.") {
        "express"
    } else {
        "javascript"
    }
}

fn is_python_fastapi_security_call(function: &str, normalized: &str) -> bool {
    if matches!(function, "OAuth2PasswordBearer" | "APIKeyCookie")
        || normalized.contains("oauth2passwordbearer")
        || normalized.contains("apikeycookie")
    {
        return true;
    }

    (matches!(function, "Depends" | "Security")
        || normalized.contains("depends(")
        || normalized.contains("security("))
        && is_python_auth_dependency_context(normalized)
}

fn is_python_auth_dependency_context(normalized: &str) -> bool {
    normalized.contains("oauth")
        || normalized.contains("security")
        || normalized.contains("apikey")
        || normalized.contains("api_key")
        || normalized.contains("bearer")
        || normalized.contains("token")
        || normalized.contains("jwt")
        || normalized.contains("auth")
        || normalized.contains("session")
        || normalized.contains("cookie")
        || normalized.contains("currentuser")
        || normalized.contains("current_user")
}

fn is_python_django_login_call(function: &str, normalized: &str) -> bool {
    matches!(function, "login" | "auth_login")
        || function.ends_with(".login")
        || normalized.contains("authlogin")
}

fn is_python_session_cycle_key_call(normalized: &str) -> bool {
    normalized.contains("session.cycle_key")
        || normalized.contains("request.session.cycle_key")
        || normalized.contains("cycle_key")
        || normalized.contains("cyclesession")
        || normalized.contains("rotate_session")
}

fn is_python_session_mutation(normalized: &str) -> bool {
    (normalized.contains("request.session")
        || normalized.contains("session")
        || normalized.contains("request.session.user")
        || normalized.contains("request.sessionuserid")
        || normalized.contains("request.sessionuser_id"))
        && (normalized.contains("user")
            || normalized.contains("account")
            || normalized.contains("role")
            || normalized.contains("admin")
            || normalized.contains("auth")
            || normalized.contains("impersonat"))
}

fn is_python_session_cookie_store_call(function: &str, normalized: &str) -> bool {
    (function.ends_with(".set_cookie") || function == "set_cookie")
        && (normalized.contains("session") || normalized.contains("sessionid"))
}

fn is_python_session_reissue_context(node: Node<'_>, source: &str) -> bool {
    let context = normalize_symbol(&ancestor_context_text(node, source));
    is_auth_transition_context(&context)
        && (context.contains("delete_cookie") || context.contains("session.flush"))
        && context.contains("set_cookie")
        && (context.contains("session") || context.contains("sessionid"))
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

fn safe_static_cookie_name(value: &str) -> Option<String> {
    let name = strip_quotes(value);
    if name.is_empty()
        || name.len() > 64
        || name.contains('=')
        || name.contains('@')
        || name.contains("://")
        || JWT_RE.is_match(&name)
        || BEARER_RE.is_match(&name)
        || looks_high_entropy(&name)
    {
        None
    } else {
        Some(name)
    }
}

fn looks_high_entropy(value: &str) -> bool {
    value.len() >= 32
        && value
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .count()
            >= value.len().saturating_sub(2)
}

fn sanitize_excerpt(excerpt: &str) -> String {
    let mut redacted = PLACEHOLDER_SECRET_RE
        .replace_all(excerpt, REDACTION)
        .to_string();
    redacted = JWT_RE.replace_all(&redacted, REDACTION).to_string();
    redacted = BEARER_RE.replace_all(&redacted, REDACTION).to_string();
    redacted = SENSITIVE_LITERAL_RE
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
            let key = captures.get(1).map(|key| key.as_str()).unwrap_or("token");
            format!("{key}: \"{REDACTION}\"")
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
    normalized.contains("refresh")
        || normalized.contains("token")
        || normalized.contains("revoke")
        || normalized.contains("provider")
        || normalized.contains("bearer")
        || normalized.contains("jwt")
        || normalized.contains("secret")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
}

fn normalize_symbol(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '/'))
        .collect::<String>()
        .to_ascii_lowercase()
}

fn normalize_symbol_without_literals(value: &str) -> String {
    normalize_symbol(&strip_string_literals(value))
}

fn strip_string_literals(value: &str) -> String {
    QUOTED_LITERAL_RE.replace_all(value, "\"\"").to_string()
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
        ArtifactType::ServiceToken => "service_token",
        ArtifactType::UnknownToken => "unknown_token",
        ArtifactType::PasswordResetToken => "password_reset_token",
        ArtifactType::EmailVerificationToken => "email_verification_token",
        ArtifactType::SessionRecord => "session_record",
        ArtifactType::OAuthAuthCodeFlow => "oauth_auth_code_flow",
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

    fn detect_refresh(language: Language, source: &str) -> DetectionOutput {
        RefreshTokenLifecycleDetector.detect(&DetectorInput {
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
    fn detects_nextresponse_cookie_delete() {
        let output = detect(
            Language::TypeScript,
            r#"
export async function DELETE() {
  const response = new NextResponse(null, { status: 204 });
  response.cookies.delete("session");
  return response;
}
"#,
        );

        assert_detector(&output, "logout.handler");
        assert_detector(&output, "logout.cookie_clear");
        assert!(output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("session")
                && artifact.framework_hints == vec!["nextjs".to_string()]
        }));
    }

    #[test]
    fn detects_express_session_middleware() {
        let output = detect(
            Language::TypeScript,
            r#"
app.use(session({ secret, cookie: { httpOnly: true, secure: true } }));
"#,
        );

        assert_detector(&output, "session.middleware");
        assert_stage(&output, "session.middleware", LifecycleStage::Store);
    }

    #[test]
    fn ignores_non_session_express_middleware_helpers() {
        let output = detect(Language::TypeScript, "app.use(sessionLogger());");

        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "session.middleware")
        );
    }

    #[test]
    fn detects_nextauth_provider_session_config() {
        let output = detect(
            Language::TypeScript,
            r#"export const GET = NextAuth({ session: { strategy: "jwt" } });"#,
        );

        let evidence = output
            .evidence
            .iter()
            .find(|evidence| evidence.detector_id == "session.provider_config")
            .expect("provider config evidence should exist");
        assert_eq!(evidence.lifecycle_stage, LifecycleStage::Store);
        assert!(evidence.dynamic);
        assert!(output.artifacts.iter().any(|artifact| {
            artifact
                .framework_hints
                .iter()
                .any(|hint| hint == "nextauth")
        }));
    }

    #[test]
    fn detects_fastapi_security_dependencies() {
        let output = detect(
            Language::Python,
            r#"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
session_cookie = APIKeyCookie(name="session")

def current_user(token: str = Security(oauth2_scheme)):
    return token
"#,
        );

        assert_detector(&output, "fastapi.security_dependency");
        assert_stage(
            &output,
            "fastapi.security_dependency",
            LifecycleStage::Validate,
        );
    }

    #[test]
    fn ignores_non_security_fastapi_dependencies() {
        let output = detect(
            Language::Python,
            r#"
def list_orders(db = Depends(get_db)):
    return db.query(Order).all()
"#,
        );

        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "fastapi.security_dependency")
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
            .map(|excerpt| excerpt.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!text.contains("PLACEHOLDER_REFRESH_TOKEN"));
        assert!(text.contains(REDACTION));
    }

    #[test]
    fn redacts_short_logout_literals() {
        let output = detect(
            Language::TypeScript,
            r#"
app.post("/logout", () => revokeRefreshToken("short-secret"));
"#,
        );

        assert_detector(&output, "logout.token_revoke");
        let text = output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!text.contains("short-secret"));
        assert!(text.contains(REDACTION));
    }

    #[test]
    fn detects_express_login_regeneration_and_session_mutation() {
        let output = detect(
            Language::TypeScript,
            r#"
app.post("/login", async (request, response) => {
  const user = await verifyPassword(request.body.email, request.body.password);
  request.session.regenerate(() => {
    request.session.userId = user.id;
  });
});
"#,
        );

        assert_detector(&output, "session.auth_transition");
        assert_detector(&output, "session.regenerate");
        assert_detector(&output, "session.store_after_auth");
        assert_stage(&output, "session.auth_transition", LifecycleStage::Issue);
        assert_stage(&output, "session.regenerate", LifecycleStage::Refresh);
    }

    #[test]
    fn detects_express_login_without_regeneration() {
        let output = detect(
            Language::TypeScript,
            r#"
app.post("/legacy-login", async (request, response) => {
  const user = await authenticate(request.body.email, request.body.password);
  request.session.userId = user.id;
});
"#,
        );

        assert_detector(&output, "session.auth_transition");
        assert_detector(&output, "session.store_after_auth");
        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "session.regenerate")
        );
    }

    #[test]
    fn non_auth_callbacks_do_not_emit_fixation_transition_evidence() {
        let output = detect(
            Language::TypeScript,
            r#"
function paymentCallback(request) {
  request.session.paymentStatus = "complete";
}
function webhookCallback(request) {
  request.session.webhookSeen = true;
}
function imageUploadCallback(request) {
  request.session.lastUpload = "ok";
}
"#,
        );

        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "session.auth_transition"),
            "{:?}",
            output.evidence
        );
    }

    #[test]
    fn detects_cookie_session_reissue_pattern() {
        let output = detect(
            Language::TypeScript,
            r#"
app.post("/signin", async (request, response) => {
  response.clearCookie("session");
  response.cookie("session", buildSignedSession(request.user.id), { httpOnly: true });
});
"#,
        );

        assert_detector(&output, "session.auth_transition");
        assert_detector(&output, "session.reissue");
        assert_stage(&output, "session.reissue", LifecycleStage::Refresh);
    }

    #[test]
    fn detects_django_cycle_key_and_framework_default_login() {
        let output = detect(
            Language::Python,
            r#"
def login_with_cycle_key(request):
    request.session.cycle_key()
    request.session["user_id"] = request.user.pk

def login_with_framework_default(request, user):
    login(request, user)
"#,
        );

        assert_detector(&output, "session.auth_transition");
        assert_detector(&output, "session.regenerate");
        assert_detector(&output, "session.framework_default_regenerate");
        assert!(output.evidence.iter().any(|evidence| {
            evidence.detector_id == "session.framework_default_regenerate"
                && evidence.framework_default
        }));
    }

    #[test]
    fn detects_privilege_elevation_without_regeneration() {
        let output = detect(
            Language::Python,
            r#"
def promote_to_admin(request):
    request.session["role"] = "admin"
"#,
        );

        assert_detector(&output, "session.privilege_transition");
        assert_detector(&output, "session.store_after_auth");
        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "session.regenerate")
        );
    }

    #[test]
    fn logout_only_does_not_emit_fixation_transition_evidence() {
        let output = detect(
            Language::TypeScript,
            r#"
app.post("/logout", (request, response) => {
  response.clearCookie("session");
  request.session.destroy();
});
"#,
        );

        assert_detector(&output, "logout.handler");
        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "session.auth_transition"
                    || evidence.detector_id == "session.privilege_transition")
        );
    }

    #[test]
    fn detects_express_refresh_rotation_and_old_token_invalidation() {
        let output = detect_refresh(
            Language::TypeScript,
            r#"
app.post("/refresh", async (request, response) => {
  const previousRefreshToken = request.cookies.refresh_token;
  const stored = await refreshTokenStore.findUnique({ where: { token: previousRefreshToken } });
  const nextRefreshToken = generateRefreshToken(stored.userId);
  await refreshTokenStore.update({ data: { usedAt: new Date() } });
  await refreshTokenStore.create({ data: { token: nextRefreshToken, expiresAt: refreshExpiry } });
  response.cookie("refresh_token", nextRefreshToken, { httpOnly: true, maxAge: 604800 });
});
"#,
        );

        assert_detector(&output, "refresh.handler");
        assert_detector(&output, "refresh.validate");
        assert_detector(&output, "refresh.issue");
        assert_detector(&output, "refresh.rotate");
        assert_detector(&output, "refresh.store");
        assert_detector(&output, "refresh.expire");
        assert_stage(&output, "refresh.rotate", LifecycleStage::Revoke);
    }

    #[test]
    fn detects_nextjs_refresh_cookie_get_and_set() {
        let output = detect_refresh(
            Language::TypeScript,
            r#"
export async function PATCH() {
  const refreshToken = cookies().get("refresh")?.value;
  await verifyRefreshJwt(refreshToken);
  const nextRefresh = await rotateRefreshToken(refreshToken);
  cookies().set("refresh", nextRefresh, { httpOnly: true, maxAge: 604800 });
}
"#,
        );

        assert_detector(&output, "refresh.handler");
        assert_detector(&output, "refresh.validate");
        assert_detector(&output, "refresh.rotate");
        assert_detector(&output, "refresh.store");
    }

    #[test]
    fn detects_fastapi_refresh_lookup_expiry_and_rotation() {
        let output = detect_refresh(
            Language::Python,
            r#"
@app.post("/refresh")
def refresh(response, refresh_token: str):
    stored = refresh_store.find_one(refresh_token)
    verify_refresh_jwt(refresh_token)
    mark_refresh_token_used(refresh_token)
    next_refresh_token = create_refresh_token(stored["user_id"])
    refresh_store.create({"token": next_refresh_token, "expires_at": refresh_expiry})
    response.set_cookie("refresh_token", next_refresh_token, max_age=604800)
"#,
        );

        assert_detector(&output, "refresh.handler");
        assert_detector(&output, "refresh.validate");
        assert_detector(&output, "refresh.issue");
        assert_detector(&output, "refresh.rotate");
        assert_detector(&output, "refresh.store");
        assert_detector(&output, "refresh.expire");
        assert_stage(&output, "refresh.rotate", LifecycleStage::Revoke);
    }

    #[test]
    fn detects_django_password_change_refresh_revocation() {
        let output = detect_refresh(
            Language::Python,
            r#"
def password_change_complete(request):
    revoke_refresh_tokens_for_user(request.user.pk)
    invalidate_user_sessions(request.user.pk)
"#,
        );

        assert_detector(&output, "refresh.revoke");
        assert_stage(&output, "refresh.revoke", LifecycleStage::Revoke);
    }

    #[test]
    fn detects_refresh_without_rotation_evidence() {
        let output = detect_refresh(
            Language::TypeScript,
            r#"
app.post("/refresh", async (request, response) => {
  const refreshToken = request.cookies.refresh_token;
  const stored = await refreshTokenStore.findUnique({ where: { token: refreshToken } });
  const nextAccessToken = issueAccessJwt(stored.userId);
  return response.json({ accessToken: nextAccessToken });
});
"#,
        );

        assert_detector(&output, "refresh.handler");
        assert_detector(&output, "refresh.validate");
        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "refresh.revoke")
        );
    }

    #[test]
    fn previous_refresh_token_lookup_does_not_imply_revocation() {
        let output = detect_refresh(
            Language::TypeScript,
            r#"
app.post("/refresh", async (request, response) => {
  const previousRefreshToken = request.cookies.refresh_token;
  const stored = await refreshTokenStore.findUnique({ where: { token: previousRefreshToken } });
  return response.json({ ok: Boolean(stored) });
});
"#,
        );

        assert_detector(&output, "refresh.handler");
        assert_detector(&output, "refresh.validate");
        assert!(
            !output.evidence.iter().any(|evidence| {
                evidence.detector_id == "refresh.rotate"
                    && evidence.lifecycle_stage == LifecycleStage::Revoke
            }),
            "previous/old token variable names are not revocation evidence: {:?}",
            output.evidence
        );
        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "refresh.revoke")
        );
    }

    #[test]
    fn detects_reuse_detection_with_family_invalidation() {
        let output = detect_refresh(
            Language::TypeScript,
            r#"
if (isRefreshTokenReuse(refreshToken)) {
  revokeRefreshTokenFamily(user.id);
}
"#,
        );

        assert_detector(&output, "refresh.reuse_detection");
        assert_stage(&output, "refresh.reuse_detection", LifecycleStage::Validate);
        assert_detector(&output, "refresh.revoke");
    }

    #[test]
    fn detects_refresh_provider_abstraction_as_dynamic() {
        let output = detect_refresh(
            Language::TypeScript,
            r#"
const rotated = await auth0.refresh(refreshToken);
"#,
        );

        let evidence = output
            .evidence
            .iter()
            .find(|evidence| evidence.detector_id == "refresh.provider")
            .expect("provider evidence");
        assert_eq!(evidence.lifecycle_stage, LifecycleStage::Refresh);
        assert!(evidence.dynamic);
    }

    #[test]
    fn refresh_detector_ignores_comments_and_redacts_placeholders() {
        let output = detect_refresh(
            Language::TypeScript,
            r#"
// revokeRefreshToken("PLACEHOLDER_REFRESH_TOKEN")
const sample = "refreshTokenStore.create({ token: PLACEHOLDER_REFRESH_TOKEN })";
app.post("/refresh", () => generateRefreshToken("PLACEHOLDER_REFRESH_TOKEN"));
"#,
        );

        assert_detector(&output, "refresh.handler");
        assert_detector(&output, "refresh.issue");
        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "refresh.revoke")
        );
        let text = output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!text.contains("PLACEHOLDER_REFRESH_TOKEN"));
        assert!(text.contains(REDACTION));
    }

    #[test]
    fn refresh_detector_redacts_short_literals_and_ignores_literal_only_matches() {
        let js_output = detect_refresh(
            Language::TypeScript,
            r#"
const sample = "refreshTokenStore.findUnique({ token: 'dev-refresh-token' })";
authProvider.refresh("dev-refresh-token");
"#,
        );
        let py_output = detect_refresh(
            Language::Python,
            r#"
sample = "revoke_refresh_token('dev-refresh-token')"
provider.refresh("dev-refresh-token")
"#,
        );

        assert_detector(&js_output, "refresh.provider");
        assert_detector(&py_output, "refresh.provider");
        for output in [&js_output, &py_output] {
            let text = output
                .evidence
                .iter()
                .filter_map(|evidence| evidence.excerpt.as_ref())
                .map(|excerpt| excerpt.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!text.contains("dev-refresh-token"));
            assert!(text.contains(REDACTION));
            assert!(
                !output
                    .evidence
                    .iter()
                    .any(|evidence| evidence.detector_id == "refresh.revoke"),
                "literal-only revoke text should not classify as refresh revoke: {:?}",
                output.evidence
            );
        }
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

    fn assert_stage(output: &DetectionOutput, detector_id: &str, stage: LifecycleStage) {
        assert!(
            output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == detector_id
                    && evidence.lifecycle_stage == stage),
            "expected detector {detector_id} at stage {stage:?} in {:?}",
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
