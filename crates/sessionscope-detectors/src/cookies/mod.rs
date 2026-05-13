use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, CookieAttributeObservation, CookieAttributeState,
    CookieAttributes, Evidence, Language, LifecycleEvidence, LifecycleStage, SanitizedExcerpt,
    SourceLocation, stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "cookie.set";
const REDACTION: &str = "[REDACTED]";

static COOKIE_VALUE_POSITIONAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(\b(?:[A-Za-z_][A-Za-z0-9_]*|cookies\(\))\s*\.\s*(?:cookie|set_cookie|set)\s*\(\s*["'][^"']+["']\s*,\s*)(["'])([^"']*)(["'])"#,
    )
    .expect("cookie positional redaction regex should compile")
});
static COOKIE_VALUE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)(\bvalue\s*[:=]\s*)(["'])([^"']*)(["'])"#)
        .expect("cookie value key redaction regex should compile")
});
static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT)[A-Z0-9_]*\b")
        .expect("placeholder secret regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static SET_COOKIE_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^(\s*[^=;\s]+)\s*=\s*([^;]*)"#).expect("set-cookie pair regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct CookieSetDetector;

impl Detector for CookieSetDetector {
    fn id(&self) -> &'static str {
        DETECTOR_ID
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        match input.language {
            Language::JavaScript | Language::TypeScript => detect_javascript_like(input, self.id()),
            Language::Python => detect_python(input, self.id()),
            _ => DetectionOutput::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CookieCall {
    api_name: &'static str,
    framework_hint: &'static str,
    line: usize,
    column: usize,
    excerpt: SanitizedExcerpt,
    cookie_name: Option<String>,
    signed: bool,
    attributes: BTreeMap<CookieAttributeKind, AttributeEvidence>,
    dynamic_options: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Wrapper {
    name: String,
    cookie_name_parameter_index: usize,
    cookie_value_parameter_index: Option<usize>,
    api_name: &'static str,
    framework_hint: &'static str,
    signed: bool,
    attributes: BTreeMap<CookieAttributeKind, AttributeEvidence>,
    dynamic_options: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OptionAlias {
    attributes: BTreeMap<CookieAttributeKind, AttributeEvidence>,
    signed: bool,
    dynamic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttributeEvidence {
    state: CookieAttributeState,
    value: Option<String>,
    confidence: Confidence,
    excerpt: SanitizedExcerpt,
    line: usize,
    column: usize,
    framework_default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CookieAttributeKind {
    HttpOnly,
    Secure,
    SameSite,
    MaxAge,
    Expires,
    Path,
    Domain,
}

impl CookieAttributeKind {
    const ALL: [Self; 7] = [
        Self::HttpOnly,
        Self::Secure,
        Self::SameSite,
        Self::MaxAge,
        Self::Expires,
        Self::Path,
        Self::Domain,
    ];

    fn wire_name(self) -> &'static str {
        match self {
            Self::HttpOnly => "http_only",
            Self::Secure => "secure",
            Self::SameSite => "same_site",
            Self::MaxAge => "max_age",
            Self::Expires => "expires",
            Self::Path => "path",
            Self::Domain => "domain",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::HttpOnly => "HttpOnly",
            Self::Secure => "Secure",
            Self::SameSite => "SameSite",
            Self::MaxAge => "Max-Age",
            Self::Expires => "Expires",
            Self::Path => "Path",
            Self::Domain => "Domain",
        }
    }

    fn lifecycle_stage(self) -> LifecycleStage {
        match self {
            Self::HttpOnly => LifecycleStage::Store,
            Self::Secure | Self::SameSite | Self::Path | Self::Domain => LifecycleStage::Transmit,
            Self::MaxAge | Self::Expires => LifecycleStage::Expire,
        }
    }
}

fn detect_javascript_like(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_javascript_like(input, input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let option_aliases = collect_js_option_aliases(root, input.source);
    let wrappers = collect_js_wrappers(root, input.source, &option_aliases);
    let mut calls = Vec::new();
    collect_js_cookie_calls(root, input.source, &[], &option_aliases, &mut calls);
    collect_js_wrapper_calls(root, input.source, &wrappers, &mut calls);

    calls_to_output(input, detector_id, calls)
}

fn detect_python(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let option_aliases = collect_python_option_aliases(root, input.source);
    let wrappers = collect_python_wrappers(root, input.source, &option_aliases);
    let mut calls = Vec::new();
    collect_python_cookie_calls(root, input.source, &[], &option_aliases, &mut calls);
    collect_python_wrapper_calls(root, input.source, &wrappers, &mut calls);

    calls_to_output(input, detector_id, calls)
}

fn scoped_key(scope: usize, name: &str) -> String {
    format!("{scope}:{name}")
}

fn scope_id(node: Node<'_>) -> usize {
    let mut current = Some(node);
    while let Some(node) = current {
        if is_function_node(node) || node.kind() == "function_definition" {
            return node.start_byte();
        }
        current = node.parent();
    }
    0
}

fn alias_lookup(
    aliases: &BTreeMap<String, OptionAlias>,
    scope: usize,
    name: &str,
) -> Option<OptionAlias> {
    aliases
        .get(&scoped_key(scope, name))
        .or_else(|| aliases.get(&scoped_key(0, name)))
        .cloned()
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

fn calls_to_output(
    input: &DetectorInput<'_>,
    detector_id: &str,
    calls: Vec<CookieCall>,
) -> DetectionOutput {
    let mut output = DetectionOutput::default();

    for call in calls {
        let location = SourceLocation {
            path: input.path.to_string(),
            line: Some(call.line),
            column: Some(call.column),
        };
        let artifact_type = artifact_type_for(call.cookie_name.as_deref(), call.signed);
        let confidence = if call.cookie_name.is_some() {
            Confidence::High
        } else {
            Confidence::Medium
        };
        let artifact_type_part = artifact_type_part(artifact_type);
        let line_part = location
            .line
            .map_or_else(String::new, |line| line.to_string());
        let column_part = location
            .column
            .map_or_else(String::new, |column| column.to_string());
        let dynamic = call.cookie_name.is_none();
        let name_part = call.cookie_name.as_deref().unwrap_or("dynamic");
        let id_parts = [
            detector_id,
            artifact_type_part,
            input.path,
            &line_part,
            &column_part,
            call.api_name,
            name_part,
        ];
        let artifact_id = stable_artifact_id(&id_parts);
        let evidence_id = stable_evidence_id(&id_parts);
        let mut lifecycle_evidence = LifecycleEvidence {
            store: vec![evidence_id.clone()],
            ..LifecycleEvidence::default()
        };
        let (cookie_attributes, mut attribute_evidence) =
            cookie_attributes_to_evidence(input, detector_id, &call, &location);

        for evidence in &attribute_evidence {
            match evidence.lifecycle_stage {
                LifecycleStage::Store => lifecycle_evidence.store.push(evidence.id.clone()),
                LifecycleStage::Transmit => lifecycle_evidence.transmit.push(evidence.id.clone()),
                LifecycleStage::Expire => lifecycle_evidence.expire.push(evidence.id.clone()),
                LifecycleStage::Issue
                | LifecycleStage::Validate
                | LifecycleStage::Refresh
                | LifecycleStage::Revoke
                | LifecycleStage::Introspect => {}
            }
        }

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type,
            display_name: call.cookie_name,
            locations: vec![location.clone()],
            lifecycle_evidence,
            confidence,
            framework_hints: vec![call.framework_hint.to_string()],
            cookie_attributes: Some(cookie_attributes),
            jwt_attributes: None,
            token_boundary_attributes: None,
        });

        output.evidence.push(Evidence {
            id: evidence_id,
            lifecycle_stage: LifecycleStage::Store,
            location,
            detector_id: detector_id.to_string(),
            confidence,
            excerpt: Some(call.excerpt),
            dynamic,
            framework_default: false,
        });
        output.evidence.append(&mut attribute_evidence);
    }

    output
}

fn cookie_attributes_to_evidence(
    input: &DetectorInput<'_>,
    detector_id: &str,
    call: &CookieCall,
    call_location: &SourceLocation,
) -> (CookieAttributes, Vec<Evidence>) {
    let mut evidence = Vec::new();
    let mut observations = BTreeMap::new();

    for kind in CookieAttributeKind::ALL {
        let attribute = call.attributes.get(&kind).cloned().unwrap_or_else(|| {
            default_attribute_for_call(
                kind,
                call,
                call_location.line.unwrap_or(1),
                call_location.column.unwrap_or(1),
            )
        });
        let line_part = attribute.line.to_string();
        let column_part = attribute.column.to_string();
        let name_part = call.cookie_name.as_deref().unwrap_or("dynamic");
        let state_part = attribute_state_part(attribute.state);
        let id_parts = [
            detector_id,
            "cookie_attribute",
            kind.wire_name(),
            state_part,
            input.path,
            &line_part,
            &column_part,
            call.api_name,
            name_part,
        ];
        let evidence_id = stable_evidence_id(&id_parts);
        observations.insert(
            kind,
            CookieAttributeObservation {
                state: attribute.state,
                value: attribute.value.clone(),
                evidence_ids: vec![evidence_id.clone()],
                confidence: attribute.confidence,
            },
        );
        evidence.push(Evidence {
            id: evidence_id,
            lifecycle_stage: kind.lifecycle_stage(),
            location: SourceLocation {
                path: input.path.to_string(),
                line: Some(attribute.line),
                column: Some(attribute.column),
            },
            detector_id: format!("cookie.attribute.{}", kind.wire_name()),
            confidence: attribute.confidence,
            excerpt: Some(attribute.excerpt),
            dynamic: attribute.state == CookieAttributeState::Dynamic,
            framework_default: attribute.framework_default,
        });
    }

    (
        CookieAttributes {
            http_only: observations
                .remove(&CookieAttributeKind::HttpOnly)
                .expect("httpOnly observation should exist"),
            secure: observations
                .remove(&CookieAttributeKind::Secure)
                .expect("secure observation should exist"),
            same_site: observations
                .remove(&CookieAttributeKind::SameSite)
                .expect("sameSite observation should exist"),
            max_age: observations
                .remove(&CookieAttributeKind::MaxAge)
                .expect("maxAge observation should exist"),
            expires: observations
                .remove(&CookieAttributeKind::Expires)
                .expect("expires observation should exist"),
            path: observations
                .remove(&CookieAttributeKind::Path)
                .expect("path observation should exist"),
            domain: observations
                .remove(&CookieAttributeKind::Domain)
                .expect("domain observation should exist"),
        },
        evidence,
    )
}

fn attribute_state_part(state: CookieAttributeState) -> &'static str {
    match state {
        CookieAttributeState::Present => "present",
        CookieAttributeState::Missing => "missing",
        CookieAttributeState::Dynamic => "dynamic",
        CookieAttributeState::FrameworkDefault => "framework_default",
        CookieAttributeState::Unknown => "unknown",
    }
}

fn default_attribute_for_call(
    kind: CookieAttributeKind,
    call: &CookieCall,
    line: usize,
    column: usize,
) -> AttributeEvidence {
    if call.dynamic_options {
        return AttributeEvidence {
            state: CookieAttributeState::Dynamic,
            value: None,
            confidence: Confidence::Medium,
            excerpt: format!(
                "{} depends on unresolved cookie options",
                kind.display_name()
            )
            .into(),
            line,
            column,
            framework_default: false,
        };
    }

    let framework_default = match call.api_name {
        "javascript.cookie" | "next.cookies.set" if kind == CookieAttributeKind::Path => Some("/"),
        "python.set_cookie" => match kind {
            CookieAttributeKind::HttpOnly => Some("false"),
            CookieAttributeKind::Secure => Some("false"),
            CookieAttributeKind::SameSite => Some("lax"),
            CookieAttributeKind::MaxAge
            | CookieAttributeKind::Expires
            | CookieAttributeKind::Domain => Some("none"),
            CookieAttributeKind::Path => Some("/"),
        },
        _ => None,
    };

    if let Some(value) = framework_default {
        return AttributeEvidence {
            state: CookieAttributeState::FrameworkDefault,
            value: Some(value.to_string()),
            confidence: Confidence::Low,
            excerpt: format!(
                "{} defaults to {} for {}",
                kind.display_name(),
                value,
                call.framework_hint
            )
            .into(),
            line,
            column,
            framework_default: true,
        };
    }

    AttributeEvidence {
        state: CookieAttributeState::Missing,
        value: None,
        confidence: Confidence::High,
        excerpt: format!("{} is omitted", kind.display_name()).into(),
        line,
        column,
        framework_default: false,
    }
}

fn artifact_type_for(cookie_name: Option<&str>, signed: bool) -> ArtifactType {
    if signed {
        return ArtifactType::SignedCookie;
    }

    let Some(cookie_name) = cookie_name else {
        return ArtifactType::Unknown;
    };
    let normalized = cookie_name.to_ascii_lowercase();
    if matches!(normalized.as_str(), "session" | "sessionid" | "sid")
        || normalized.contains("session")
    {
        ArtifactType::SessionCookie
    } else {
        ArtifactType::Unknown
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

fn node_line_column(node: Node<'_>) -> (usize, usize) {
    let position = node.start_position();
    (position.row + 1, position.column + 1)
}

fn excerpt_around_node_with_redactions(
    source: &str,
    node: Node<'_>,
    sensitive_nodes: &[Node<'_>],
) -> SanitizedExcerpt {
    let target_line = node.start_position().row;
    let lines = source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return SanitizedExcerpt(String::new());
    }

    let start = target_line.saturating_sub(1);
    let end = (target_line + 2).min(lines.len());
    let mut excerpt = lines[start..end].join("\n");
    for sensitive_node in sensitive_nodes {
        let sensitive_text = node_text(*sensitive_node, source);
        if !sensitive_text.trim().is_empty() {
            excerpt = excerpt.replace(&sensitive_text, REDACTION);
        }
    }
    SanitizedExcerpt(redact_detector_excerpt(&excerpt))
}

fn redact_detector_excerpt(input: &str) -> String {
    let mut output = COOKIE_VALUE_POSITIONAL_RE
        .replace_all(input, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = COOKIE_VALUE_KEY_RE
        .replace_all(&output, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = JWT_RE.replace_all(&output, REDACTION).to_string();
    PLACEHOLDER_SECRET_RE
        .replace_all(&output, REDACTION)
        .to_string()
}

fn collect_js_cookie_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    option_aliases: &BTreeMap<String, OptionAlias>,
    calls: &mut Vec<CookieCall>,
) {
    if is_function_node(node) {
        let parameters = function_parameters_for_js_function(node, source);
        collect_js_children(node, source, &parameters, option_aliases, calls);
        return;
    }

    if node.kind() == "call_expression"
        && let Some(call) = js_cookie_call(node, source, function_parameters, option_aliases)
    {
        calls.push(call);
    }
    if node.kind() == "call_expression" {
        calls.extend(js_set_cookie_header_calls(node, source));
    }

    collect_js_children(node, source, function_parameters, option_aliases, calls);
}

fn collect_js_children<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    option_aliases: &BTreeMap<String, OptionAlias>,
    calls: &mut Vec<CookieCall>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_cookie_calls(child, source, function_parameters, option_aliases, calls);
    }
}

fn collect_python_cookie_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    option_aliases: &BTreeMap<String, OptionAlias>,
    calls: &mut Vec<CookieCall>,
) {
    if node.kind() == "function_definition" {
        let parameters = function_parameters_for_python_function(node, source);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_python_cookie_calls(child, source, &parameters, option_aliases, calls);
        }
        return;
    }

    if node.kind() == "call"
        && let Some(call) = python_cookie_call(node, source, function_parameters, option_aliases)
    {
        calls.push(call);
    }
    if node.kind() == "call" {
        calls.extend(python_set_cookie_header_calls(node, source));
    } else if node.kind() == "assignment" {
        calls.extend(python_set_cookie_header_assignments(node, source));
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_cookie_calls(child, source, function_parameters, option_aliases, calls);
    }
}

fn js_cookie_call<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> Option<CookieCall> {
    let function = node.child_by_field_name("function")?;
    let (api_name, framework_hint) = js_supported_cookie_api(function, source)?;
    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let name_argument = argument_nodes.first().copied()?;

    if is_identifier_in_parameters(name_argument, source, function_parameters) {
        return None;
    }

    let object_form_name = (api_name == "next.cookies.set")
        .then(|| object_property_value(name_argument, source, "name"))
        .flatten();
    let options = if api_name == "next.cookies.set" && is_object_literal(name_argument) {
        js_options_from_object(name_argument, source).unwrap_or_else(dynamic_option_alias)
    } else {
        argument_nodes
            .get(2)
            .map(|options| js_options_from_node(*options, source, option_aliases))
            .unwrap_or_else(|| OptionAlias {
                attributes: BTreeMap::new(),
                signed: false,
                dynamic: false,
            })
    };

    Some(CookieCall {
        api_name,
        framework_hint,
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node_with_redactions(
            source,
            node,
            &js_cookie_value_nodes(&argument_nodes, source),
        ),
        cookie_name: object_form_name
            .and_then(|node| string_literal_value(node, source))
            .or_else(|| string_literal_value(name_argument, source)),
        signed: options.signed,
        attributes: options.attributes,
        dynamic_options: options.dynamic,
    })
}

fn python_cookie_call<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> Option<CookieCall> {
    let function = node.child_by_field_name("function")?;
    if !python_supported_cookie_api(function, source) {
        return None;
    }

    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let name_argument = first_python_cookie_name_argument(&argument_nodes, source)?;

    if is_identifier_in_parameters(name_argument, source, function_parameters) {
        return None;
    }

    let options = python_options_from_arguments(&argument_nodes, source, option_aliases);

    Some(CookieCall {
        api_name: "python.set_cookie",
        framework_hint: "python",
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node_with_redactions(
            source,
            node,
            &python_cookie_value_nodes(&argument_nodes, source),
        ),
        cookie_name: string_literal_value(name_argument, source),
        signed: false,
        attributes: options.attributes,
        dynamic_options: options.dynamic,
    })
}

fn js_set_cookie_header_calls(node: Node<'_>, source: &str) -> Vec<CookieCall> {
    let Some(function) = node.child_by_field_name("function") else {
        return Vec::new();
    };
    let Some((api_name, framework_hint)) = js_supported_set_cookie_header_api(function, source)
    else {
        return Vec::new();
    };
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let argument_nodes = named_children(arguments);
    if !argument_nodes
        .first()
        .and_then(|argument| string_literal_value(*argument, source))
        .is_some_and(|value| value.eq_ignore_ascii_case("set-cookie"))
    {
        return Vec::new();
    }
    let Some(value_node) = argument_nodes.get(1).copied() else {
        return Vec::new();
    };

    set_cookie_header_calls_from_value_node(
        source,
        value_node,
        api_name,
        framework_hint,
        node_line_column(node),
    )
}

fn python_set_cookie_header_calls(node: Node<'_>, source: &str) -> Vec<CookieCall> {
    let Some(function) = node.child_by_field_name("function") else {
        return Vec::new();
    };
    let Some((api_name, framework_hint)) = python_supported_set_cookie_header_api(function, source)
    else {
        return Vec::new();
    };
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let argument_nodes = named_children(arguments);
    if !argument_nodes
        .first()
        .and_then(|argument| string_literal_value(*argument, source))
        .is_some_and(|value| value.eq_ignore_ascii_case("set-cookie"))
    {
        return Vec::new();
    }
    let Some(value_node) = argument_nodes.get(1).copied() else {
        return Vec::new();
    };

    set_cookie_header_calls_from_value_node(
        source,
        value_node,
        api_name,
        framework_hint,
        node_line_column(node),
    )
}

fn python_set_cookie_header_assignments(node: Node<'_>, source: &str) -> Vec<CookieCall> {
    let children = named_children(node);
    let (Some(left), Some(right)) = (children.first().copied(), children.get(1).copied()) else {
        return Vec::new();
    };
    if !python_set_cookie_subscript(left, source) {
        return Vec::new();
    }

    set_cookie_header_calls_from_value_node(
        source,
        right,
        "set-cookie.header",
        "set-cookie-header",
        node_line_column(node),
    )
}

fn set_cookie_header_calls_from_value_node(
    source: &str,
    value_node: Node<'_>,
    api_name: &'static str,
    framework_hint: &'static str,
    fallback_location: (usize, usize),
) -> Vec<CookieCall> {
    let literal_values = string_literals_from_node(value_node, source);
    if literal_values.is_empty() {
        let (line, column) = fallback_location;
        return vec![CookieCall {
            api_name,
            framework_hint,
            line,
            column,
            excerpt: SanitizedExcerpt(redact_set_cookie_header_values(&node_text(
                value_node, source,
            ))),
            cookie_name: None,
            signed: false,
            attributes: BTreeMap::new(),
            dynamic_options: true,
        }];
    }

    literal_values
        .into_iter()
        .filter_map(|(value, node)| {
            set_cookie_call_from_header(
                &value,
                api_name,
                framework_hint,
                node_line_column(node),
                SanitizedExcerpt(redact_set_cookie_header_values(&value)),
            )
        })
        .collect()
}

fn set_cookie_call_from_header(
    header: &str,
    api_name: &'static str,
    framework_hint: &'static str,
    location: (usize, usize),
    excerpt: SanitizedExcerpt,
) -> Option<CookieCall> {
    let mut segments = header.split(';');
    let first = segments.next()?.trim();
    let captures = SET_COOKIE_PAIR_RE.captures(first)?;
    let cookie_name = captures.get(1)?.as_str().trim().to_string();
    if cookie_name.is_empty() {
        return None;
    }

    let mut attributes = BTreeMap::new();
    for segment in segments {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
        let value = parts.next().map(str::trim);
        if let Some((kind, attribute_value)) = header_attribute_kind_and_value(key, value) {
            attributes.insert(
                kind,
                AttributeEvidence {
                    state: CookieAttributeState::Present,
                    value: Some(redact_detector_excerpt(&normalize_attribute_value(
                        kind,
                        attribute_value,
                    ))),
                    confidence: Confidence::High,
                    excerpt: SanitizedExcerpt(redact_set_cookie_header_values(&format!(
                        "{}={attribute_value}",
                        kind.display_name()
                    ))),
                    line: location.0,
                    column: location.1,
                    framework_default: false,
                },
            );
        }
    }

    Some(CookieCall {
        api_name,
        framework_hint,
        line: location.0,
        column: location.1,
        excerpt,
        cookie_name: Some(cookie_name),
        signed: false,
        attributes,
        dynamic_options: false,
    })
}

fn header_attribute_kind_and_value<'a>(
    key: &str,
    value: Option<&'a str>,
) -> Option<(CookieAttributeKind, &'a str)> {
    let normalized = key.to_ascii_lowercase();
    match normalized.as_str() {
        "httponly" => Some((CookieAttributeKind::HttpOnly, "true")),
        "secure" => Some((CookieAttributeKind::Secure, "true")),
        "samesite" => value.map(|value| (CookieAttributeKind::SameSite, value)),
        "max-age" | "maxage" => value.map(|value| (CookieAttributeKind::MaxAge, value)),
        "expires" => value.map(|value| (CookieAttributeKind::Expires, value)),
        "path" => value.map(|value| (CookieAttributeKind::Path, value)),
        "domain" => value.map(|value| (CookieAttributeKind::Domain, value)),
        _ => None,
    }
}

fn js_supported_set_cookie_header_api(
    function: Node<'_>,
    source: &str,
) -> Option<(&'static str, &'static str)> {
    if !is_member_expression(function) {
        return None;
    }
    let property = function.child_by_field_name("property")?;
    match node_text(property, source).as_str() {
        "setHeader" | "set" | "append" => Some(("set-cookie.header", "set-cookie-header")),
        _ => None,
    }
}

fn python_supported_set_cookie_header_api(
    function: Node<'_>,
    source: &str,
) -> Option<(&'static str, &'static str)> {
    if function.kind() != "attribute" {
        return None;
    }
    let attribute = function.child_by_field_name("attribute")?;
    match node_text(attribute, source).as_str() {
        "append" | "add" | "setdefault" => Some(("set-cookie.header", "set-cookie-header")),
        _ => None,
    }
}

fn python_set_cookie_subscript(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "subscript" {
        return false;
    }
    let text = node_text(node, source);
    text.to_ascii_lowercase().contains("headers")
        && text.to_ascii_lowercase().contains("set-cookie")
}

fn js_supported_cookie_api(
    function: Node<'_>,
    source: &str,
) -> Option<(&'static str, &'static str)> {
    if !is_member_expression(function) {
        return None;
    }

    let property = function.child_by_field_name("property")?;
    let property_name = node_text(property, source);

    if property_name == "cookie" {
        return Some(("javascript.cookie", "express"));
    }

    if property_name == "set"
        && function
            .child_by_field_name("object")
            .is_some_and(|object| is_cookies_call(object, source))
    {
        return Some(("next.cookies.set", "nextjs"));
    }

    None
}

fn python_supported_cookie_api(function: Node<'_>, source: &str) -> bool {
    if function.kind() == "attribute" {
        return function
            .child_by_field_name("attribute")
            .is_some_and(|attribute| node_text(attribute, source) == "set_cookie");
    }

    node_text(function, source).ends_with(".set_cookie")
}

fn first_python_cookie_name_argument<'tree>(
    argument_nodes: &[Node<'tree>],
    source: &str,
) -> Option<Node<'tree>> {
    for argument in argument_nodes {
        if argument.kind() == "keyword_argument" {
            if let Some(name) = argument.child_by_field_name("name") {
                if !matches!(node_text(name, source).as_str(), "key" | "name") {
                    continue;
                }
            } else if !node_text(*argument, source).starts_with("key=")
                && !node_text(*argument, source).starts_with("name=")
            {
                continue;
            }

            return argument.child_by_field_name("value").or_else(|| {
                argument
                    .named_child_count()
                    .checked_sub(1)
                    .and_then(|index| argument.named_child(index as u32))
            });
        }

        return Some(*argument);
    }

    None
}

fn js_cookie_value_nodes<'tree>(argument_nodes: &[Node<'tree>], source: &str) -> Vec<Node<'tree>> {
    if let Some(value_argument) = argument_nodes.get(1).copied() {
        return vec![value_argument];
    }

    argument_nodes
        .first()
        .and_then(|argument| object_property_value(*argument, source, "value"))
        .into_iter()
        .collect()
}

fn python_cookie_value_nodes<'tree>(
    argument_nodes: &[Node<'tree>],
    source: &str,
) -> Vec<Node<'tree>> {
    let mut values = Vec::new();
    if let Some(value_argument) = argument_nodes.get(1).copied()
        && value_argument.kind() != "keyword_argument"
    {
        values.push(value_argument);
    }

    for argument in argument_nodes {
        if argument.kind() == "keyword_argument"
            && let Some(name) = argument.child_by_field_name("name")
            && node_text(name, source) == "value"
            && let Some(value) = argument.child_by_field_name("value")
        {
            values.push(value);
        }
    }
    values
}

fn object_property_value<'tree>(
    node: Node<'tree>,
    source: &str,
    property_name: &str,
) -> Option<Node<'tree>> {
    if !is_object_literal(node) {
        return None;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some((key, value)) = object_pair(child)
            && strip_quotes(&node_text(key, source)) == property_name
        {
            return Some(value);
        }
    }
    None
}

fn is_cookies_call(node: Node<'_>, source: &str) -> bool {
    node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .is_some_and(|function| node_text(function, source) == "cookies")
}

fn is_member_expression(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "member_expression" | "optional_chain" | "subscript_expression"
    )
}

fn object_has_signed_true(node: Node<'_>, source: &str) -> bool {
    if (node.kind() == "pair" || node.kind() == "property_assignment")
        && let (Some(key), Some(value)) = (
            node.child_by_field_name("key"),
            node.child_by_field_name("value"),
        )
    {
        return strip_quotes(&node_text(key, source)) == "signed"
            && node_text(value, source) == "true";
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| object_has_signed_true(child, source))
}

fn collect_js_option_aliases(root: Node<'_>, source: &str) -> BTreeMap<String, OptionAlias> {
    let mut aliases = BTreeMap::new();
    collect_js_option_aliases_from_node(root, source, &mut aliases);
    aliases
}

fn collect_js_option_aliases_from_node(
    node: Node<'_>,
    source: &str,
    aliases: &mut BTreeMap<String, OptionAlias>,
) {
    if node.kind() == "variable_declarator"
        && let (Some(name), Some(value)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
        && let Some(alias) = js_options_from_object(value, source)
    {
        aliases.insert(scoped_key(scope_id(node), &node_text(name, source)), alias);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_option_aliases_from_node(child, source, aliases);
    }
}

fn collect_python_option_aliases(root: Node<'_>, source: &str) -> BTreeMap<String, OptionAlias> {
    let mut aliases = BTreeMap::new();
    collect_python_option_aliases_from_node(root, source, &mut aliases);
    aliases
}

fn collect_python_option_aliases_from_node(
    node: Node<'_>,
    source: &str,
    aliases: &mut BTreeMap<String, OptionAlias>,
) {
    if node.kind() == "assignment" {
        let children = named_children(node);
        if let (Some(name), Some(value)) = (children.first(), children.get(1))
            && name.kind() == "identifier"
            && let Some(alias) = python_options_from_dictionary(*value, source)
        {
            aliases.insert(scoped_key(scope_id(node), &node_text(*name, source)), alias);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_option_aliases_from_node(child, source, aliases);
    }
}

fn js_options_from_node(
    node: Node<'_>,
    source: &str,
    aliases: &BTreeMap<String, OptionAlias>,
) -> OptionAlias {
    if is_object_literal(node) {
        return js_options_from_object(node, source).unwrap_or_else(dynamic_option_alias);
    }

    if node.kind() == "identifier" {
        return alias_lookup(aliases, scope_id(node), &node_text(node, source))
            .unwrap_or_else(dynamic_option_alias);
    }

    dynamic_option_alias()
}

fn js_options_from_object(node: Node<'_>, source: &str) -> Option<OptionAlias> {
    if !is_object_literal(node) {
        return None;
    }

    let mut alias = OptionAlias {
        attributes: BTreeMap::new(),
        signed: object_has_signed_true(node, source),
        dynamic: false,
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some((key, value)) = object_pair(child) {
            let key_name = strip_quotes(&node_text(key, source));
            if let Some(kind) = js_attribute_kind(&key_name) {
                alias
                    .attributes
                    .insert(kind, attribute_from_value(kind, value, source));
            }
        } else if is_js_spread_or_computed_property(child) {
            alias.dynamic = true;
        }
    }

    Some(alias)
}

fn python_options_from_arguments(
    argument_nodes: &[Node<'_>],
    source: &str,
    aliases: &BTreeMap<String, OptionAlias>,
) -> OptionAlias {
    let mut options = OptionAlias {
        attributes: BTreeMap::new(),
        signed: false,
        dynamic: false,
    };

    for argument in argument_nodes {
        if argument.kind() == "keyword_argument" {
            if let (Some(name), Some(value)) = (
                argument.child_by_field_name("name"),
                argument.child_by_field_name("value"),
            ) && let Some(kind) = python_attribute_kind(&node_text(name, source))
            {
                options
                    .attributes
                    .insert(kind, attribute_from_value(kind, value, source));
            }
        } else if is_dictionary_splat(*argument, source) {
            if let Some(alias) = python_splat_alias(*argument, source, aliases) {
                options.attributes.extend(alias.attributes);
                options.dynamic |= alias.dynamic;
            } else {
                options.dynamic = true;
            }
        }
    }

    options
}

fn python_splat_alias(
    node: Node<'_>,
    source: &str,
    aliases: &BTreeMap<String, OptionAlias>,
) -> Option<OptionAlias> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "identifier")
        .and_then(|identifier| {
            alias_lookup(aliases, scope_id(node), &node_text(identifier, source))
        })
}

fn python_options_from_dictionary(node: Node<'_>, source: &str) -> Option<OptionAlias> {
    if node.kind() != "dictionary" {
        return None;
    }

    let mut alias = OptionAlias {
        attributes: BTreeMap::new(),
        signed: false,
        dynamic: false,
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some((key, value)) = object_pair(child) {
            let key_name = strip_quotes(&node_text(key, source));
            if let Some(kind) = python_attribute_kind(&key_name) {
                alias
                    .attributes
                    .insert(kind, attribute_from_value(kind, value, source));
            }
        }
    }

    Some(alias)
}

fn dynamic_option_alias() -> OptionAlias {
    OptionAlias {
        attributes: BTreeMap::new(),
        signed: false,
        dynamic: true,
    }
}

fn is_js_spread_or_computed_property(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "spread_element" | "computed_property_name" | "method_definition"
    )
}

fn object_pair(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if !matches!(node.kind(), "pair" | "property_assignment") {
        return None;
    }

    Some((
        node.child_by_field_name("key")?,
        node.child_by_field_name("value")?,
    ))
}

fn is_object_literal(node: Node<'_>) -> bool {
    matches!(node.kind(), "object" | "object_pattern")
}

fn is_dictionary_splat(node: Node<'_>, source: &str) -> bool {
    matches!(
        node.kind(),
        "dictionary_splat" | "dictionary_splat_pattern" | "keyword_argument"
    ) && node_text(node, source).trim_start().starts_with("**")
}

fn js_attribute_kind(key: &str) -> Option<CookieAttributeKind> {
    match key {
        "httpOnly" => Some(CookieAttributeKind::HttpOnly),
        "secure" => Some(CookieAttributeKind::Secure),
        "sameSite" => Some(CookieAttributeKind::SameSite),
        "maxAge" => Some(CookieAttributeKind::MaxAge),
        "expires" => Some(CookieAttributeKind::Expires),
        "path" => Some(CookieAttributeKind::Path),
        "domain" => Some(CookieAttributeKind::Domain),
        _ => None,
    }
}

fn python_attribute_kind(key: &str) -> Option<CookieAttributeKind> {
    match key {
        "httponly" => Some(CookieAttributeKind::HttpOnly),
        "secure" => Some(CookieAttributeKind::Secure),
        "samesite" => Some(CookieAttributeKind::SameSite),
        "max_age" => Some(CookieAttributeKind::MaxAge),
        "expires" => Some(CookieAttributeKind::Expires),
        "path" => Some(CookieAttributeKind::Path),
        "domain" => Some(CookieAttributeKind::Domain),
        _ => None,
    }
}

fn attribute_from_value(
    kind: CookieAttributeKind,
    value_node: Node<'_>,
    source: &str,
) -> AttributeEvidence {
    let value = node_text(value_node, source);
    let normalized = value.to_ascii_lowercase();
    let (state, confidence) = if is_missing_literal(&normalized) {
        (CookieAttributeState::Missing, Confidence::High)
    } else if is_present_literal(value_node, &normalized) {
        (CookieAttributeState::Present, Confidence::High)
    } else {
        (CookieAttributeState::Dynamic, Confidence::Medium)
    };
    let (line, column) = node_line_column(value_node);

    AttributeEvidence {
        state,
        value: Some(redact_detector_excerpt(&normalize_attribute_value(
            kind, &value,
        ))),
        confidence,
        excerpt: redact_detector_excerpt(&format!("{}: {}", kind.display_name(), value)).into(),
        line,
        column,
        framework_default: false,
    }
}

fn is_missing_literal(normalized: &str) -> bool {
    matches!(
        normalized.trim(),
        "false" | "none" | "null" | "undefined" | "\"\"" | "''"
    )
}

fn is_present_literal(value_node: Node<'_>, normalized: &str) -> bool {
    matches!(
        normalized.trim(),
        "true" | "lax" | "\"lax\"" | "'lax'" | "\"strict\"" | "'strict'" | "\"none\"" | "'none'"
    ) || matches!(
        value_node.kind(),
        "string" | "integer" | "float" | "number" | "true" | "false"
    ) && normalized.trim() != "false"
}

fn normalize_attribute_value(_kind: CookieAttributeKind, value: &str) -> String {
    strip_quotes(value.trim())
}

fn collect_js_wrappers(
    root: Node<'_>,
    source: &str,
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> BTreeMap<String, Wrapper> {
    let mut wrappers = BTreeMap::new();
    collect_js_wrappers_from_node(root, source, option_aliases, &mut wrappers);
    wrappers
}

fn collect_js_wrappers_from_node(
    node: Node<'_>,
    source: &str,
    option_aliases: &BTreeMap<String, OptionAlias>,
    wrappers: &mut BTreeMap<String, Wrapper>,
) {
    if is_function_node(node)
        && let Some(wrapper) = js_wrapper(node, source, option_aliases)
    {
        wrappers.insert(wrapper.name.clone(), wrapper);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_wrappers_from_node(child, source, option_aliases, wrappers);
    }
}

fn js_wrapper(
    node: Node<'_>,
    source: &str,
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> Option<Wrapper> {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .or_else(|| js_variable_function_name(node, source))?;
    let parameters = function_parameters_for_js_function(node, source);
    if parameters.is_empty() {
        return None;
    }

    let (cookie_name_parameter_index, cookie_value_parameter_index, template) =
        find_js_wrapper_template(node, source, &parameters, option_aliases)?;
    Some(Wrapper {
        name,
        cookie_name_parameter_index,
        cookie_value_parameter_index,
        api_name: template.api_name,
        framework_hint: template.framework_hint,
        signed: template.signed,
        attributes: template.attributes,
        dynamic_options: template.dynamic_options,
    })
}

fn find_js_wrapper_template(
    node: Node<'_>,
    source: &str,
    parameters: &[String],
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> Option<(usize, Option<usize>, CookieCall)> {
    if node.kind() == "call_expression" {
        let function = node.child_by_field_name("function")?;
        js_supported_cookie_api(function, source)?;
        let arguments = node.child_by_field_name("arguments")?;
        let argument_nodes = named_children(arguments);
        let name_argument = argument_nodes.first().copied()?;
        let cookie_name_parameter_index = parameters
            .iter()
            .position(|parameter| node_text(name_argument, source) == *parameter)?;
        let cookie_value_parameter_index = argument_nodes.get(1).and_then(|value_argument| {
            parameters
                .iter()
                .position(|parameter| node_text(*value_argument, source) == *parameter)
        });
        let template = js_cookie_call(node, source, &[], option_aliases)?;
        return Some((
            cookie_name_parameter_index,
            cookie_value_parameter_index,
            template,
        ));
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(template) = find_js_wrapper_template(child, source, parameters, option_aliases)
        {
            return Some(template);
        }
    }

    None
}

fn collect_js_wrapper_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    wrappers: &BTreeMap<String, Wrapper>,
    calls: &mut Vec<CookieCall>,
) {
    if node.kind() == "call_expression"
        && let Some(call) = js_wrapper_call(node, source, wrappers)
    {
        calls.push(call);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_wrapper_calls(child, source, wrappers, calls);
    }
}

fn js_wrapper_call(
    node: Node<'_>,
    source: &str,
    wrappers: &BTreeMap<String, Wrapper>,
) -> Option<CookieCall> {
    let function = node.child_by_field_name("function")?;
    let wrapper = wrappers.get(&node_text(function, source))?;
    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let name_argument = argument_nodes.get(wrapper.cookie_name_parameter_index)?;
    let cookie_name = string_literal_value(*name_argument, source)?;

    Some(CookieCall {
        api_name: wrapper.api_name,
        framework_hint: "wrapper",
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node_with_redactions(
            source,
            node,
            &wrapper_value_nodes(&argument_nodes, wrapper.cookie_value_parameter_index),
        ),
        cookie_name: Some(cookie_name),
        signed: wrapper.signed,
        attributes: wrapper.attributes.clone(),
        dynamic_options: wrapper.dynamic_options,
    })
}

fn collect_python_wrappers(
    root: Node<'_>,
    source: &str,
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> BTreeMap<String, Wrapper> {
    let mut wrappers = BTreeMap::new();
    collect_python_wrappers_from_node(root, source, option_aliases, &mut wrappers);
    wrappers
}

fn collect_python_wrappers_from_node(
    node: Node<'_>,
    source: &str,
    option_aliases: &BTreeMap<String, OptionAlias>,
    wrappers: &mut BTreeMap<String, Wrapper>,
) {
    if node.kind() == "function_definition"
        && let Some(wrapper) = python_wrapper(node, source, option_aliases)
    {
        wrappers.insert(wrapper.name.clone(), wrapper);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_wrappers_from_node(child, source, option_aliases, wrappers);
    }
}

fn python_wrapper(
    node: Node<'_>,
    source: &str,
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> Option<Wrapper> {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source))?;
    let parameters = function_parameters_for_python_function(node, source);
    if parameters.is_empty() {
        return None;
    }

    let (cookie_name_parameter_index, cookie_value_parameter_index, template) =
        find_python_wrapper_template(node, source, &parameters, option_aliases)?;
    Some(Wrapper {
        name,
        cookie_name_parameter_index,
        cookie_value_parameter_index,
        api_name: template.api_name,
        framework_hint: template.framework_hint,
        signed: template.signed,
        attributes: template.attributes,
        dynamic_options: template.dynamic_options,
    })
}

fn find_python_wrapper_template(
    node: Node<'_>,
    source: &str,
    parameters: &[String],
    option_aliases: &BTreeMap<String, OptionAlias>,
) -> Option<(usize, Option<usize>, CookieCall)> {
    if node.kind() == "call" {
        let function = node.child_by_field_name("function")?;
        if !python_supported_cookie_api(function, source) {
            return None;
        }
        let arguments = node.child_by_field_name("arguments")?;
        let argument_nodes = named_children(arguments);
        let name_argument = first_python_cookie_name_argument(&argument_nodes, source)?;
        let cookie_name_parameter_index = parameters
            .iter()
            .position(|parameter| node_text(name_argument, source) == *parameter)?;
        let cookie_value_parameter_index = python_cookie_value_nodes(&argument_nodes, source)
            .first()
            .and_then(|value_argument| {
                parameters
                    .iter()
                    .position(|parameter| node_text(*value_argument, source) == *parameter)
            });
        let template = python_cookie_call(node, source, &[], option_aliases)?;
        return Some((
            cookie_name_parameter_index,
            cookie_value_parameter_index,
            template,
        ));
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(template) =
            find_python_wrapper_template(child, source, parameters, option_aliases)
        {
            return Some(template);
        }
    }

    None
}

fn collect_python_wrapper_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    wrappers: &BTreeMap<String, Wrapper>,
    calls: &mut Vec<CookieCall>,
) {
    if node.kind() == "call"
        && let Some(call) = python_wrapper_call(node, source, wrappers)
    {
        calls.push(call);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_wrapper_calls(child, source, wrappers, calls);
    }
}

fn python_wrapper_call(
    node: Node<'_>,
    source: &str,
    wrappers: &BTreeMap<String, Wrapper>,
) -> Option<CookieCall> {
    let function = node.child_by_field_name("function")?;
    let wrapper = wrappers.get(&node_text(function, source))?;
    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let name_argument = argument_nodes.get(wrapper.cookie_name_parameter_index)?;
    let cookie_name = string_literal_value(*name_argument, source)?;

    Some(CookieCall {
        api_name: wrapper.api_name,
        framework_hint: "wrapper",
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node_with_redactions(
            source,
            node,
            &wrapper_value_nodes(&argument_nodes, wrapper.cookie_value_parameter_index),
        ),
        cookie_name: Some(cookie_name),
        signed: wrapper.signed,
        attributes: wrapper.attributes.clone(),
        dynamic_options: wrapper.dynamic_options,
    })
}

fn wrapper_value_nodes<'tree>(
    argument_nodes: &[Node<'tree>],
    value_parameter_index: Option<usize>,
) -> Vec<Node<'tree>> {
    value_parameter_index
        .and_then(|index| argument_nodes.get(index).copied())
        .into_iter()
        .collect()
}

fn is_function_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "function" | "arrow_function"
    )
}

fn js_variable_function_name(node: Node<'_>, source: &str) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "variable_declarator" {
        return None;
    }
    parent
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
}

fn function_parameters_for_js_function(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_children(parameters)
        .into_iter()
        .filter_map(|parameter| parameter_name(parameter, source))
        .collect()
}

fn function_parameters_for_python_function(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_children(parameters)
        .into_iter()
        .filter_map(|parameter| parameter_name(parameter, source))
        .collect()
}

fn parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "required_parameter" => Some(node_text(node, source)),
        "typed_parameter" | "optional_parameter" | "default_parameter" => node
            .child_by_field_name("pattern")
            .or_else(|| node.child_by_field_name("name"))
            .map(|name| node_text(name, source)),
        _ => None,
    }
}

fn is_identifier_in_parameters(node: Node<'_>, source: &str, parameters: &[String]) -> bool {
    matches!(node.kind(), "identifier")
        && parameters
            .iter()
            .any(|parameter| parameter == &node_text(node, source))
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn string_literal_value(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "string" => parse_string_text(&node_text(node, source)),
        _ => None,
    }
}

fn string_literals_from_node<'tree>(node: Node<'tree>, source: &str) -> Vec<(String, Node<'tree>)> {
    if let Some(value) = string_literal_value(node, source) {
        return vec![(value, node)];
    }

    if !matches!(node.kind(), "array" | "list") {
        return Vec::new();
    }

    named_children(node)
        .into_iter()
        .filter_map(|child| string_literal_value(child, source).map(|value| (value, child)))
        .collect()
}

fn parse_string_text(text: &str) -> Option<String> {
    let mut chars = text.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let end = text.chars().last()?;
    if end != quote {
        return None;
    }
    Some(text[quote.len_utf8()..text.len() - quote.len_utf8()].to_string())
}

fn strip_quotes(text: &str) -> String {
    parse_string_text(text).unwrap_or_else(|| text.to_string())
}

fn node_text(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes())
        .unwrap_or_default()
        .to_string()
}

fn redact_set_cookie_header_values(input: &str) -> String {
    let mut output = input.to_string();
    for captures in SET_COOKIE_PAIR_RE.captures_iter(input) {
        let Some(full) = captures.get(0) else {
            continue;
        };
        let Some(name) = captures.get(1) else {
            continue;
        };
        output = output.replace(
            full.as_str(),
            &format!("{}={REDACTION}", name.as_str().trim()),
        );
    }
    redact_detector_excerpt(&output)
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{ArtifactType, Confidence, CookieAttributeState, Language};

    use super::CookieSetDetector;
    use crate::{Detector, DetectorInput};

    fn detect(language: Language, source: &str) -> crate::DetectionOutput {
        CookieSetDetector.detect(&DetectorInput {
            path: "src/app.ts",
            language,
            source,
        })
    }

    #[test]
    fn detects_signed_express_cookie_literal() {
        let output = detect(
            Language::TypeScript,
            r#"response.cookie("session", token, { httpOnly: true, secure: true, signed: true });"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.evidence.len(), 8);
        assert_eq!(
            output.artifacts[0].artifact_type,
            ArtifactType::SignedCookie
        );
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert_eq!(output.artifacts[0].confidence, Confidence::High);
        assert_eq!(output.artifacts[0].locations[0].line, Some(1));
        assert_eq!(output.artifacts[0].locations[0].column, Some(1));
        assert!(
            output.artifacts[0]
                .lifecycle_evidence
                .store
                .contains(&output.evidence[0].id)
        );
    }

    #[test]
    fn ignores_cookie_reads_clear_calls_comments_and_strings() {
        let output = detect(
            Language::TypeScript,
            r#"
const value = request.cookies.session;
response.clearCookie("session");
// response.cookie("commented", token)
const text = "response.cookie(\"string\", token)";
"#,
        );

        assert!(output.artifacts.is_empty());
        assert!(output.evidence.is_empty());
    }

    #[test]
    fn detects_nextjs_cookies_set() {
        let output = detect(
            Language::TypeScript,
            r#"cookies().set("access", accessJwt, { httpOnly: true });"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].artifact_type, ArtifactType::Unknown);
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("access"));
        assert_eq!(output.artifacts[0].framework_hints, vec!["nextjs"]);
    }

    #[test]
    fn detects_python_response_set_cookie() {
        let output = detect(
            Language::Python,
            r#"response.set_cookie("session", token, httponly=True, secure=True)"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(
            output.artifacts[0].artifact_type,
            ArtifactType::SessionCookie
        );
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert_eq!(output.evidence[0].location.line, Some(1));
    }

    #[test]
    fn detects_javascript_set_cookie_header_strings_and_arrays() {
        let output = detect(
            Language::TypeScript,
            r#"
response.setHeader("Set-Cookie", [
  "session=PLACEHOLDER_RESET_TOKEN; HttpOnly; Secure; SameSite=Lax; Max-Age=2678401; Path=/; Domain=.example.com",
  "prefs=light; SameSite=Strict"
]);
"#,
        );

        assert_eq!(output.artifacts.len(), 2);
        let session = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("session"))
            .expect("session cookie should be detected");
        assert_eq!(session.artifact_type, ArtifactType::SessionCookie);
        assert_eq!(session.framework_hints, vec!["set-cookie-header"]);
        let attributes = session
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(attributes.same_site.value.as_deref(), Some("Lax"));
        assert_eq!(attributes.max_age.value.as_deref(), Some("2678401"));
        assert_eq!(attributes.path.value.as_deref(), Some("/"));
        assert_eq!(attributes.domain.value.as_deref(), Some(".example.com"));
        assert!(!detected_text(&output).contains("PLACEHOLDER_RESET_TOKEN"));
    }

    #[test]
    fn detects_python_set_cookie_header_assignment_and_append() {
        let output = detect(
            Language::Python,
            r#"
response.headers["Set-Cookie"] = "session=PLACEHOLDER_RESET_TOKEN; HttpOnly; Secure; SameSite=Lax; Max-Age=900"
response.headers.append("Set-Cookie", "legacy_session=PLACEHOLDER_RESET_TOKEN; SameSite=None; Path=/")
"#,
        );

        assert_eq!(output.artifacts.len(), 2);
        assert!(output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("session")
                && artifact.artifact_type == ArtifactType::SessionCookie
        }));
        let legacy = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("legacy_session"))
            .expect("legacy session should be detected");
        let attributes = legacy
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.secure.state, CookieAttributeState::Missing);
        assert_eq!(attributes.same_site.value.as_deref(), Some("None"));
        assert_eq!(attributes.path.value.as_deref(), Some("/"));
        assert!(!detected_text(&output).contains("PLACEHOLDER_RESET_TOKEN"));
    }

    #[test]
    fn dynamic_set_cookie_header_value_marks_attributes_dynamic() {
        let output = detect(
            Language::TypeScript,
            r#"response.setHeader("Set-Cookie", buildSessionCookie());"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].display_name, None);
        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Dynamic);
        assert_eq!(attributes.secure.state, CookieAttributeState::Dynamic);
        assert!(output.evidence[0].dynamic);
    }

    #[test]
    fn dynamic_cookie_name_emits_medium_confidence_without_display_name() {
        let output = detect(Language::TypeScript, "response.cookie(cookieName, token);");

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].display_name, None);
        assert_eq!(output.artifacts[0].confidence, Confidence::Medium);
        assert!(output.evidence[0].dynamic);
    }

    #[test]
    fn reports_precise_location_for_multiline_call() {
        let output = detect(
            Language::TypeScript,
            "const ok = true;\n  response.cookie(\n    \"session\",\n    token\n  );",
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].locations[0].line, Some(2));
        assert_eq!(output.artifacts[0].locations[0].column, Some(3));
    }

    #[test]
    fn detects_simple_javascript_wrapper_calls() {
        let output = detect(
            Language::TypeScript,
            r#"
function setAuthCookie(response, name, value) {
  response.cookie(name, value, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 900,
    signed: true
  });
}

setAuthCookie(response, "session", token);
"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(
            output.artifacts[0].artifact_type,
            ArtifactType::SignedCookie
        );
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert_eq!(output.artifacts[0].framework_hints, vec!["wrapper"]);
        assert_eq!(output.artifacts[0].locations[0].line, Some(12));

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(attributes.same_site.value.as_deref(), Some("lax"));
        assert_eq!(attributes.max_age.value.as_deref(), Some("900"));
        let http_only_evidence = output
            .evidence
            .iter()
            .find(|evidence| evidence.id == attributes.http_only.evidence_ids[0])
            .expect("httpOnly evidence should exist");
        assert_eq!(http_only_evidence.location.line, Some(4));
    }

    #[test]
    fn detects_simple_python_wrapper_calls() {
        let output = detect(
            Language::Python,
            r#"
def set_auth_cookie(response, name, value):
    response.set_cookie(
        name,
        value,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=900,
    )

set_auth_cookie(response, "session", token)
"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert_eq!(output.artifacts[0].framework_hints, vec!["wrapper"]);
        assert_eq!(output.artifacts[0].locations[0].line, Some(12));

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(attributes.same_site.value.as_deref(), Some("strict"));
        assert_eq!(attributes.max_age.value.as_deref(), Some("900"));
        let secure_evidence = output
            .evidence
            .iter()
            .find(|evidence| evidence.id == attributes.secure.evidence_ids[0])
            .expect("secure evidence should exist");
        assert_eq!(secure_evidence.location.line, Some(7));
    }

    #[test]
    fn extracts_all_explicit_express_attributes() {
        let output = detect(
            Language::TypeScript,
            r#"response.cookie("session", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 900,
  expires: "soon",
  path: "/",
  domain: "example.test"
});"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(attributes.same_site.value.as_deref(), Some("lax"));
        assert_eq!(attributes.max_age.value.as_deref(), Some("900"));
        assert_eq!(attributes.expires.value.as_deref(), Some("soon"));
        assert_eq!(attributes.path.value.as_deref(), Some("/"));
        assert_eq!(attributes.domain.value.as_deref(), Some("example.test"));
        assert!(!output.artifacts[0].lifecycle_evidence.transmit.is_empty());
        assert!(!output.artifacts[0].lifecycle_evidence.expire.is_empty());
    }

    #[test]
    fn extracts_nextjs_attributes_from_option_alias() {
        let output = detect(
            Language::TypeScript,
            r#"
const cookieOptions = { httpOnly: true, secure: true, sameSite: "strict" };
cookies().set("access", token, cookieOptions);
"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(attributes.same_site.value.as_deref(), Some("strict"));
        assert_eq!(
            attributes.path.state,
            CookieAttributeState::FrameworkDefault
        );
    }

    #[test]
    fn marks_missing_and_dynamic_express_attributes() {
        let output = detect(
            Language::TypeScript,
            r#"response.cookie("session", token, {
  httpOnly: false,
  secure: process.env.NODE_ENV === "production"
});"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Missing);
        assert_eq!(attributes.secure.state, CookieAttributeState::Dynamic);
        assert_eq!(attributes.secure.confidence, Confidence::Medium);
        assert_eq!(attributes.same_site.state, CookieAttributeState::Missing);
        assert_eq!(
            attributes.path.state,
            CookieAttributeState::FrameworkDefault
        );
    }

    #[test]
    fn extracts_fastapi_attributes_and_documented_defaults() {
        let output = detect(
            Language::Python,
            r#"
response.set_cookie(
    "session",
    token,
    httponly=True,
    secure=True,
    samesite="lax",
    max_age=900,
)
"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(attributes.same_site.value.as_deref(), Some("lax"));
        assert_eq!(attributes.max_age.value.as_deref(), Some("900"));
        assert_eq!(
            attributes.path.state,
            CookieAttributeState::FrameworkDefault
        );
        assert_eq!(
            attributes.expires.state,
            CookieAttributeState::FrameworkDefault
        );
        assert_eq!(
            attributes.domain.state,
            CookieAttributeState::FrameworkDefault
        );
    }

    #[test]
    fn extracts_python_attributes_from_dict_splat_alias() {
        let output = detect(
            Language::Python,
            r#"
cookie_options = {"httponly": True, "secure": True, "samesite": "strict"}
response.set_cookie("session", token, **cookie_options)
"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(attributes.same_site.value.as_deref(), Some("strict"));
    }

    #[test]
    fn direct_detector_redacts_nextjs_object_cookie_values() {
        let output = detect(
            Language::TypeScript,
            r#"cookies().set({ name: "session", value: "short-secret", httpOnly: true });"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert!(!detected_text(&output).contains("short-secret"));
        assert!(detected_text(&output).contains("[REDACTED]"));
    }

    #[test]
    fn direct_detector_redacts_python_keyword_cookie_values() {
        let output = detect(
            Language::Python,
            r#"response.set_cookie(key="session", value="short-secret", httponly=True)"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert!(!detected_text(&output).contains("short-secret"));
        assert!(detected_text(&output).contains("[REDACTED]"));
    }

    #[test]
    fn javascript_aliases_resolve_in_lexical_scope_only() {
        let output = detect(
            Language::TypeScript,
            r#"
function first(response, token) {
  const opts = { secure: true, httpOnly: true };
  response.cookie("first_session", token, opts);
}
function second(response, token) {
  const opts = { secure: false, httpOnly: false };
  response.cookie("second_session", token, opts);
}
"#,
        );

        let first = artifact_named(&output, "first_session");
        let second = artifact_named(&output, "second_session");
        let first_attributes = first.cookie_attributes.as_ref().expect("first attributes");
        let second_attributes = second
            .cookie_attributes
            .as_ref()
            .expect("second attributes");
        assert_eq!(first_attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(
            first_attributes.http_only.state,
            CookieAttributeState::Present
        );
        assert_eq!(
            second_attributes.secure.state,
            CookieAttributeState::Missing
        );
        assert_eq!(
            second_attributes.http_only.state,
            CookieAttributeState::Missing
        );
    }

    #[test]
    fn python_aliases_resolve_in_lexical_scope_only() {
        let output = detect(
            Language::Python,
            r#"
def first(response, token):
    opts = {"secure": True, "httponly": True}
    response.set_cookie("first_session", token, **opts)

def second(response, token):
    opts = {"secure": False, "httponly": False}
    response.set_cookie("second_session", token, **opts)
"#,
        );

        let first = artifact_named(&output, "first_session");
        let second = artifact_named(&output, "second_session");
        let first_attributes = first.cookie_attributes.as_ref().expect("first attributes");
        let second_attributes = second
            .cookie_attributes
            .as_ref()
            .expect("second attributes");
        assert_eq!(first_attributes.secure.state, CookieAttributeState::Present);
        assert_eq!(
            first_attributes.http_only.state,
            CookieAttributeState::Present
        );
        assert_eq!(
            second_attributes.secure.state,
            CookieAttributeState::Missing
        );
        assert_eq!(
            second_attributes.http_only.state,
            CookieAttributeState::Missing
        );
    }

    #[test]
    fn unresolved_javascript_option_identifier_marks_unobserved_attributes_dynamic() {
        let output = detect(
            Language::TypeScript,
            r#"response.cookie("session", token, cookieOptions);"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Dynamic);
        assert_eq!(attributes.http_only.confidence, Confidence::Medium);
        assert_eq!(attributes.secure.state, CookieAttributeState::Dynamic);
        assert_eq!(attributes.secure.confidence, Confidence::Medium);
    }

    #[test]
    fn javascript_object_spread_marks_unobserved_attributes_dynamic() {
        let output = detect(
            Language::TypeScript,
            r#"response.cookie("session", token, { ...cookieOptions, httpOnly: true });"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Present);
        assert_eq!(attributes.secure.state, CookieAttributeState::Dynamic);
        assert_eq!(attributes.secure.confidence, Confidence::Medium);
    }

    #[test]
    fn unknown_python_kwargs_marks_unobserved_attributes_dynamic() {
        let output = detect(
            Language::Python,
            r#"response.set_cookie("session", token, **cookie_options)"#,
        );

        let attributes = output.artifacts[0]
            .cookie_attributes
            .as_ref()
            .expect("cookie attributes should exist");
        assert_eq!(attributes.http_only.state, CookieAttributeState::Dynamic);
        assert_eq!(attributes.http_only.confidence, Confidence::Medium);
        assert_eq!(attributes.secure.state, CookieAttributeState::Dynamic);
        assert_eq!(attributes.secure.confidence, Confidence::Medium);
    }

    fn detected_text(output: &crate::DetectionOutput) -> String {
        let excerpts = output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.0.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let attribute_values = output
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.cookie_attributes.as_ref())
            .flat_map(|attributes| {
                [
                    &attributes.http_only,
                    &attributes.secure,
                    &attributes.same_site,
                    &attributes.max_age,
                    &attributes.expires,
                    &attributes.path,
                    &attributes.domain,
                ]
                .into_iter()
                .filter_map(|observation| observation.value.as_deref())
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!("{excerpts}\n{attribute_values}")
    }

    fn artifact_named<'a>(
        output: &'a crate::DetectionOutput,
        display_name: &str,
    ) -> &'a sessionscope_model::Artifact {
        output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some(display_name))
            .expect("named artifact should exist")
    }
}
