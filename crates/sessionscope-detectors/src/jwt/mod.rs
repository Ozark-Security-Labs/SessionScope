use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, JwtAttributeObservation, JwtAttributeState,
    JwtAttributes, Language, LifecycleEvidence, LifecycleStage, SanitizedExcerpt, SourceLocation,
    stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "jwt.validation";
const REDACTION: &str = "[REDACTED]";

static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT)[A-Z0-9_]*\b")
        .expect("placeholder secret regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static LONG_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(secret|private[_-]?key|signing[_-]?key|token|jwt)\s*[:=]\s*["'][^"']*["']"#)
        .expect("sensitive literal regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct JwtDetector;

impl Detector for JwtDetector {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JwtOperation {
    Issue,
    Validate,
    DecodeWithoutVerify,
}

impl JwtOperation {
    fn lifecycle_stage(self) -> LifecycleStage {
        match self {
            Self::Issue => LifecycleStage::Issue,
            Self::Validate => LifecycleStage::Validate,
            Self::DecodeWithoutVerify => LifecycleStage::Introspect,
        }
    }

    fn value(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Validate => "validate",
            Self::DecodeWithoutVerify => "decode_without_verify",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JwtField {
    Operation,
    Algorithm,
    KeyReference,
    Issuer,
    Audience,
    Expiration,
}

impl JwtField {
    const ALL: [Self; 6] = [
        Self::Operation,
        Self::Algorithm,
        Self::KeyReference,
        Self::Issuer,
        Self::Audience,
        Self::Expiration,
    ];

    fn wire_name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Algorithm => "algorithm",
            Self::KeyReference => "key_reference",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expiration => "expiration",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Algorithm => "algorithm",
            Self::KeyReference => "key reference",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expiration => "expiration",
        }
    }

    fn lifecycle_stage(self, operation: JwtOperation) -> LifecycleStage {
        match self {
            Self::Expiration => LifecycleStage::Expire,
            _ => operation.lifecycle_stage(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JwtFieldEvidence {
    state: JwtAttributeState,
    value: Option<String>,
    confidence: Confidence,
    line: usize,
    column: usize,
    excerpt: SanitizedExcerpt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JwtCall {
    operation: JwtOperation,
    api_name: &'static str,
    framework_hint: &'static str,
    line: usize,
    column: usize,
    excerpt: SanitizedExcerpt,
    display_name: Option<String>,
    artifact_type: ArtifactType,
    fields: BTreeMap<JwtField, JwtFieldEvidence>,
}

#[derive(Debug, Clone, Default)]
struct JsImports {
    jsonwebtoken_namespaces: BTreeSet<String>,
    jsonwebtoken_functions: BTreeMap<String, &'static str>,
    jose_functions: BTreeMap<String, &'static str>,
}

#[derive(Debug, Clone, Default)]
struct PyImports {
    jwt_modules: BTreeSet<String>,
    jwt_functions: BTreeMap<String, &'static str>,
}

#[derive(Debug, Clone, Default)]
struct FieldSet {
    fields: BTreeMap<JwtField, JwtFieldEvidence>,
    dynamic: bool,
}

fn detect_javascript_like(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_javascript_like(input, input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let imports = collect_js_imports(input.source);
    let option_aliases = collect_js_option_aliases(root, input.source);
    let mut calls = Vec::new();
    collect_js_calls(
        root,
        input.source,
        &imports,
        &option_aliases,
        None,
        &mut calls,
    );

    calls_to_output(input, detector_id, calls)
}

fn detect_python(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let imports = collect_python_imports(input.source);
    let option_aliases = collect_python_option_aliases(root, input.source);
    let mut calls = Vec::new();
    collect_python_calls(
        root,
        input.source,
        &imports,
        &option_aliases,
        None,
        &mut calls,
    );

    calls_to_output(input, detector_id, calls)
}

fn calls_to_output(
    input: &DetectorInput<'_>,
    detector_id: &str,
    calls: Vec<JwtCall>,
) -> DetectionOutput {
    let mut groups: BTreeMap<String, Vec<JwtCall>> = BTreeMap::new();
    for call in calls {
        let key = format!(
            "{}:{}:{}",
            artifact_type_part(call.artifact_type),
            call.display_name.as_deref().unwrap_or("dynamic"),
            if call.display_name.is_none() {
                call.line
            } else {
                0
            }
        );
        groups.entry(key).or_default().push(call);
    }

    let mut output = DetectionOutput::default();

    for (_, calls) in groups {
        let first = calls.first().expect("group should contain a call");
        let display_name = first.display_name.clone();
        let artifact_type = first.artifact_type;
        let confidence = if display_name.is_some() {
            Confidence::High
        } else {
            Confidence::Medium
        };
        let name_part = display_name.as_deref().unwrap_or("dynamic");
        let id_parts = [
            detector_id,
            artifact_type_part(artifact_type),
            input.path,
            name_part,
        ];
        let artifact_id = stable_artifact_id(&id_parts);
        let mut lifecycle_evidence = LifecycleEvidence::default();
        let mut locations = Vec::new();
        let mut framework_hints = BTreeSet::new();
        let mut field_observations: BTreeMap<JwtField, Vec<JwtFieldEvidence>> = BTreeMap::new();
        let mut field_evidence_ids: BTreeMap<JwtField, Vec<sessionscope_model::EvidenceId>> =
            BTreeMap::new();
        let mut operation_evidence_ids = Vec::new();

        for call in &calls {
            let location = SourceLocation {
                path: input.path.to_string(),
                line: Some(call.line),
                column: Some(call.column),
            };
            locations.push(location.clone());
            framework_hints.insert(call.framework_hint.to_string());

            let line_part = call.line.to_string();
            let column_part = call.column.to_string();
            let evidence_id = stable_evidence_id(&[
                detector_id,
                call.operation.value(),
                input.path,
                &line_part,
                &column_part,
                call.api_name,
                name_part,
            ]);
            push_lifecycle_id(
                &mut lifecycle_evidence,
                call.operation.lifecycle_stage(),
                evidence_id.clone(),
            );
            operation_evidence_ids.push(evidence_id.clone());
            output.evidence.push(Evidence {
                id: evidence_id,
                lifecycle_stage: call.operation.lifecycle_stage(),
                location,
                detector_id: format!("jwt.{}", call.operation.value()),
                confidence,
                excerpt: Some(call.excerpt.clone()),
                dynamic: false,
                framework_default: false,
            });

            let operation_field = JwtFieldEvidence {
                state: JwtAttributeState::Present,
                value: Some(call.operation.value().to_string()),
                confidence,
                line: call.line,
                column: call.column,
                excerpt: call.excerpt.clone(),
            };
            field_observations
                .entry(JwtField::Operation)
                .or_default()
                .push(operation_field);

            for (field, observation) in &call.fields {
                let line_part = observation.line.to_string();
                let column_part = observation.column.to_string();
                let state_part = jwt_state_part(observation.state);
                let evidence_id = stable_evidence_id(&[
                    detector_id,
                    "jwt_attribute",
                    field.wire_name(),
                    state_part,
                    input.path,
                    &line_part,
                    &column_part,
                    call.api_name,
                    name_part,
                ]);
                push_lifecycle_id(
                    &mut lifecycle_evidence,
                    field.lifecycle_stage(call.operation),
                    evidence_id.clone(),
                );
                output.evidence.push(Evidence {
                    id: evidence_id.clone(),
                    lifecycle_stage: field.lifecycle_stage(call.operation),
                    location: SourceLocation {
                        path: input.path.to_string(),
                        line: Some(observation.line),
                        column: Some(observation.column),
                    },
                    detector_id: format!("jwt.attribute.{}", field.wire_name()),
                    confidence: observation.confidence,
                    excerpt: Some(observation.excerpt.clone()),
                    dynamic: observation.state == JwtAttributeState::Dynamic,
                    framework_default: false,
                });
                field_evidence_ids
                    .entry(*field)
                    .or_default()
                    .push(evidence_id);
                field_observations
                    .entry(*field)
                    .or_default()
                    .push(JwtFieldEvidence {
                        state: observation.state,
                        value: observation.value.clone(),
                        confidence: observation.confidence,
                        line: observation.line,
                        column: observation.column,
                        excerpt: observation.excerpt.clone(),
                    });
            }
        }

        locations.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.column.cmp(&right.column))
        });
        locations.dedup();

        let mut jwt_attributes = aggregate_jwt_attributes(field_observations);
        jwt_attributes.operation.evidence_ids = operation_evidence_ids;
        apply_field_evidence_ids(&mut jwt_attributes, field_evidence_ids);

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type,
            display_name,
            locations,
            lifecycle_evidence,
            confidence,
            framework_hints: framework_hints.into_iter().collect(),
            cookie_attributes: None,
            jwt_attributes: Some(jwt_attributes),
        });
    }

    output
}

fn apply_field_evidence_ids(
    attributes: &mut JwtAttributes,
    mut evidence_ids: BTreeMap<JwtField, Vec<sessionscope_model::EvidenceId>>,
) {
    attributes.algorithm.evidence_ids = evidence_ids
        .remove(&JwtField::Algorithm)
        .unwrap_or_default();
    attributes.key_reference.evidence_ids = evidence_ids
        .remove(&JwtField::KeyReference)
        .unwrap_or_default();
    attributes.issuer.evidence_ids = evidence_ids.remove(&JwtField::Issuer).unwrap_or_default();
    attributes.audience.evidence_ids = evidence_ids.remove(&JwtField::Audience).unwrap_or_default();
    attributes.expiration.evidence_ids = evidence_ids
        .remove(&JwtField::Expiration)
        .unwrap_or_default();
}

fn aggregate_jwt_attributes(
    observations: BTreeMap<JwtField, Vec<JwtFieldEvidence>>,
) -> JwtAttributes {
    let mut fields = BTreeMap::new();
    for field in JwtField::ALL {
        fields.insert(field, aggregate_field(field, observations.get(&field)));
    }

    JwtAttributes {
        operation: fields
            .remove(&JwtField::Operation)
            .expect("operation exists"),
        algorithm: fields
            .remove(&JwtField::Algorithm)
            .expect("algorithm exists"),
        key_reference: fields
            .remove(&JwtField::KeyReference)
            .expect("key reference exists"),
        issuer: fields.remove(&JwtField::Issuer).expect("issuer exists"),
        audience: fields.remove(&JwtField::Audience).expect("audience exists"),
        expiration: fields
            .remove(&JwtField::Expiration)
            .expect("expiration exists"),
    }
}

fn aggregate_field(
    field: JwtField,
    observations: Option<&Vec<JwtFieldEvidence>>,
) -> JwtAttributeObservation {
    let Some(observations) = observations else {
        return JwtAttributeObservation {
            state: JwtAttributeState::Unknown,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::Low,
        };
    };

    let state = if observations
        .iter()
        .any(|observation| observation.state == JwtAttributeState::Missing)
    {
        JwtAttributeState::Missing
    } else if observations
        .iter()
        .any(|observation| observation.state == JwtAttributeState::Dynamic)
    {
        JwtAttributeState::Dynamic
    } else if observations
        .iter()
        .any(|observation| observation.state == JwtAttributeState::Present)
    {
        JwtAttributeState::Present
    } else {
        JwtAttributeState::Unknown
    };
    let confidence = observations
        .iter()
        .map(|observation| observation.confidence)
        .max()
        .unwrap_or(Confidence::Low);
    let mut values = observations
        .iter()
        .filter_map(|observation| observation.value.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if values.len() > 3 {
        values.truncate(3);
        values.push("...".to_string());
    }

    JwtAttributeObservation {
        state,
        value: if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        },
        evidence_ids: Vec::new(),
        confidence: if field == JwtField::Operation {
            Confidence::High
        } else {
            confidence
        },
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

fn collect_js_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &JsImports,
    option_aliases: &BTreeMap<String, FieldSet>,
    function_name: Option<&str>,
    calls: &mut Vec<JwtCall>,
) {
    let local_function_name = js_function_name(node, source);
    let active_function_name = local_function_name.as_deref().or(function_name);

    if node.kind() == "call_expression"
        && let Some(call) = js_jwt_call(node, source, imports, option_aliases, active_function_name)
    {
        calls.push(call);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_calls(
            child,
            source,
            imports,
            option_aliases,
            active_function_name,
            calls,
        );
    }
}

fn js_jwt_call<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &JsImports,
    option_aliases: &BTreeMap<String, FieldSet>,
    function_name: Option<&str>,
) -> Option<JwtCall> {
    let function = node.child_by_field_name("function")?;
    let call_text = node_text(node, source);

    if is_jose_sign_chain(&call_text, imports) {
        return Some(js_jose_sign_call(node, source, function_name));
    }

    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let mut api_name = None;
    let mut framework_hint = None;
    let mut operation = None;

    if is_member_expression(function) {
        let property = function.child_by_field_name("property")?;
        let property_name = node_text(property, source);
        let object_name = function
            .child_by_field_name("object")
            .map(|object| node_text(object, source))
            .unwrap_or_default();
        if imports.jsonwebtoken_namespaces.contains(&object_name)
            && matches!(property_name.as_str(), "sign" | "verify" | "decode")
        {
            api_name = Some(match property_name.as_str() {
                "sign" => "jsonwebtoken.sign",
                "verify" => "jsonwebtoken.verify",
                "decode" => "jsonwebtoken.decode",
                _ => unreachable!(),
            });
            framework_hint = Some("jsonwebtoken");
            operation = Some(match property_name.as_str() {
                "sign" => JwtOperation::Issue,
                "verify" => JwtOperation::Validate,
                "decode" => JwtOperation::DecodeWithoutVerify,
                _ => unreachable!(),
            });
        }
    } else if function.kind() == "identifier" {
        let local_name = node_text(function, source);
        if let Some(original) = imports.jsonwebtoken_functions.get(local_name.as_str()) {
            api_name = Some(match *original {
                "sign" => "jsonwebtoken.sign",
                "verify" => "jsonwebtoken.verify",
                "decode" => "jsonwebtoken.decode",
                _ => return None,
            });
            framework_hint = Some("jsonwebtoken");
            operation = Some(match *original {
                "sign" => JwtOperation::Issue,
                "verify" => JwtOperation::Validate,
                "decode" => JwtOperation::DecodeWithoutVerify,
                _ => return None,
            });
        } else if let Some(original) = imports.jose_functions.get(local_name.as_str()) {
            api_name = Some(match *original {
                "jwtVerify" => "jose.jwtVerify",
                "decodeJwt" => "jose.decodeJwt",
                _ => return None,
            });
            framework_hint = Some("jose");
            operation = Some(match *original {
                "jwtVerify" => JwtOperation::Validate,
                "decodeJwt" => JwtOperation::DecodeWithoutVerify,
                _ => return None,
            });
        }
    }

    let api_name = api_name?;
    let framework_hint = framework_hint?;
    let operation = operation?;
    let (line, column) = node_line_column(node);
    let mut fields = BTreeMap::new();

    match api_name {
        "jsonwebtoken.sign" => add_js_sign_fields(
            &mut fields,
            source,
            &argument_nodes,
            option_aliases,
            line,
            column,
        ),
        "jsonwebtoken.verify" | "jose.jwtVerify" => add_js_verify_fields(
            &mut fields,
            source,
            &argument_nodes,
            option_aliases,
            line,
            column,
            api_name == "jose.jwtVerify",
        ),
        "jsonwebtoken.decode" | "jose.decodeJwt" => {}
        _ => {}
    }

    let display_name = infer_jwt_display_name(function_name, node, source);
    let artifact_type = artifact_type_for_name(display_name.as_deref());
    Some(JwtCall {
        operation,
        api_name,
        framework_hint,
        line,
        column,
        excerpt: excerpt_for_node(source, node),
        display_name,
        artifact_type,
        fields,
    })
}

fn js_jose_sign_call<'tree>(
    node: Node<'tree>,
    source: &str,
    function_name: Option<&str>,
) -> JwtCall {
    let (line, column) = node_line_column(node);
    let text = node_text(node, source);
    let mut fields = BTreeMap::new();

    add_regex_chain_field(
        &mut fields,
        JwtField::Algorithm,
        &text,
        r#"\.setProtectedHeader\s*\(\s*\{[^}]*\balg\s*:\s*([^,}]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::Issuer,
        &text,
        r#"\.setIssuer\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::Audience,
        &text,
        r#"\.setAudience\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::Expiration,
        &text,
        r#"\.setExpirationTime\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::KeyReference,
        &text,
        r#"\.sign\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_missing_for_issue_fields(&mut fields, line, column);

    let display_name = infer_jwt_display_name(function_name, node, source);
    let artifact_type = artifact_type_for_name(display_name.as_deref());
    JwtCall {
        operation: JwtOperation::Issue,
        api_name: "jose.SignJWT.sign",
        framework_hint: "jose",
        line,
        column,
        excerpt: excerpt_for_node(source, node),
        display_name,
        artifact_type,
        fields,
    }
}

fn add_js_sign_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &BTreeMap<String, FieldSet>,
    line: usize,
    column: usize,
) {
    add_key_reference(fields, source, argument_nodes.get(1).copied(), line, column);
    if let Some(payload) = argument_nodes.first().copied() {
        add_object_field(
            fields,
            JwtField::Issuer,
            payload,
            source,
            &["iss"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Audience,
            payload,
            source,
            &["aud"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Expiration,
            payload,
            source,
            &["exp"],
            line,
            column,
        );
    }
    if let Some(options) = argument_nodes.get(2).copied() {
        add_js_options_fields(
            fields,
            source,
            options,
            option_aliases,
            &[
                (JwtField::Algorithm, &["algorithm", "algorithms"][..]),
                (JwtField::Issuer, &["issuer"][..]),
                (JwtField::Audience, &["audience"][..]),
                (JwtField::Expiration, &["expiresIn", "expires"][..]),
            ],
            line,
            column,
        );
    }
    add_missing_for_issue_fields(fields, line, column);
}

fn add_js_verify_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &BTreeMap<String, FieldSet>,
    line: usize,
    column: usize,
    jose: bool,
) {
    add_key_reference(fields, source, argument_nodes.get(1).copied(), line, column);
    if let Some(options) = argument_nodes.get(2).copied() {
        add_js_options_fields(
            fields,
            source,
            options,
            option_aliases,
            &[
                (JwtField::Algorithm, &["algorithms", "algorithm"][..]),
                (JwtField::Issuer, &["issuer"][..]),
                (JwtField::Audience, &["audience"][..]),
            ],
            line,
            column,
        );
    }
    if jose && argument_nodes.get(2).is_none() {
        add_missing(fields, JwtField::Issuer, line, column);
        add_missing(fields, JwtField::Audience, line, column);
    } else {
        add_missing_for_verify_fields(fields, line, column);
    }
}

fn add_js_options_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    node: Node<'_>,
    aliases: &BTreeMap<String, FieldSet>,
    wanted: &[(JwtField, &[&str])],
    line: usize,
    column: usize,
) {
    if is_object_literal(node) {
        for (field, names) in wanted {
            add_object_field(fields, *field, node, source, names, line, column);
        }
        if object_has_dynamic_spread(node, source) {
            for (field, _) in wanted {
                fields
                    .entry(*field)
                    .or_insert_with(|| dynamic_field(*field, line, column));
            }
        }
    } else if node.kind() == "identifier" {
        let alias_name = node_text(node, source);
        if let Some(alias) = aliases.get(&alias_name) {
            for (field, _) in wanted {
                if let Some(value) = alias.fields.get(field) {
                    fields.entry(*field).or_insert_with(|| value.clone());
                } else if alias.dynamic {
                    fields
                        .entry(*field)
                        .or_insert_with(|| dynamic_field(*field, line, column));
                }
            }
        } else {
            for (field, _) in wanted {
                fields
                    .entry(*field)
                    .or_insert_with(|| dynamic_field(*field, line, column));
            }
        }
    } else {
        for (field, _) in wanted {
            fields
                .entry(*field)
                .or_insert_with(|| dynamic_field(*field, line, column));
        }
    }
}

fn collect_python_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &PyImports,
    option_aliases: &BTreeMap<String, FieldSet>,
    function_name: Option<&str>,
    calls: &mut Vec<JwtCall>,
) {
    let local_function_name = python_function_name(node, source);
    let active_function_name = local_function_name.as_deref().or(function_name);

    if node.kind() == "call"
        && let Some(call) =
            python_jwt_call(node, source, imports, option_aliases, active_function_name)
    {
        calls.push(call);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_calls(
            child,
            source,
            imports,
            option_aliases,
            active_function_name,
            calls,
        );
    }
}

fn python_jwt_call<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &PyImports,
    option_aliases: &BTreeMap<String, FieldSet>,
    function_name: Option<&str>,
) -> Option<JwtCall> {
    let function = node.child_by_field_name("function")?;
    let mut api_name = None;
    let mut operation_name = None;

    if function.kind() == "attribute" {
        let attribute = function.child_by_field_name("attribute")?;
        let attribute_name = node_text(attribute, source);
        let object_name = function
            .child_by_field_name("object")
            .map(|object| node_text(object, source))
            .unwrap_or_default();
        if imports.jwt_modules.contains(&object_name)
            && matches!(attribute_name.as_str(), "encode" | "decode")
        {
            api_name = Some(match attribute_name.as_str() {
                "encode" => "pyjwt.encode",
                "decode" => "pyjwt.decode",
                _ => unreachable!(),
            });
            operation_name = Some(attribute_name);
        }
    } else if function.kind() == "identifier" {
        let local_name = node_text(function, source);
        if let Some(original) = imports.jwt_functions.get(local_name.as_str()) {
            api_name = Some(match *original {
                "encode" => "pyjwt.encode",
                "decode" => "pyjwt.decode",
                _ => return None,
            });
            operation_name = Some((*original).to_string());
        }
    }

    let api_name = api_name?;
    let operation_name = operation_name?;
    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let (line, column) = node_line_column(node);
    let mut fields = BTreeMap::new();

    let operation = if operation_name == "encode" {
        add_python_encode_fields(
            &mut fields,
            source,
            &argument_nodes,
            option_aliases,
            line,
            column,
        );
        JwtOperation::Issue
    } else if python_decode_disables_verification(source, &argument_nodes, option_aliases) {
        JwtOperation::DecodeWithoutVerify
    } else {
        add_python_decode_fields(
            &mut fields,
            source,
            &argument_nodes,
            option_aliases,
            line,
            column,
        );
        JwtOperation::Validate
    };

    let display_name = infer_jwt_display_name(function_name, node, source);
    let artifact_type = artifact_type_for_name(display_name.as_deref());
    Some(JwtCall {
        operation,
        api_name,
        framework_hint: "pyjwt",
        line,
        column,
        excerpt: excerpt_for_node(source, node),
        display_name,
        artifact_type,
        fields,
    })
}

fn add_python_encode_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &BTreeMap<String, FieldSet>,
    line: usize,
    column: usize,
) {
    add_key_reference(fields, source, argument_nodes.get(1).copied(), line, column);
    if let Some(payload) = argument_nodes.first().copied() {
        add_object_field(
            fields,
            JwtField::Issuer,
            payload,
            source,
            &["iss"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Audience,
            payload,
            source,
            &["aud"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Expiration,
            payload,
            source,
            &["exp"],
            line,
            column,
        );
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "algorithm") {
        add_present_node(fields, JwtField::Algorithm, value, source);
    }
    if let Some(options) = python_keyword_value(argument_nodes, source, "headers") {
        add_object_field(
            fields,
            JwtField::Algorithm,
            options,
            source,
            &["alg"],
            line,
            column,
        );
    }
    if let Some(options) = python_keyword_value(argument_nodes, source, "options") {
        add_python_options_fields(fields, source, options, option_aliases, line, column);
    }
    add_missing_for_issue_fields(fields, line, column);
}

fn add_python_decode_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &BTreeMap<String, FieldSet>,
    line: usize,
    column: usize,
) {
    add_key_reference(fields, source, argument_nodes.get(1).copied(), line, column);
    if let Some(value) = python_keyword_value(argument_nodes, source, "algorithms") {
        add_present_node(fields, JwtField::Algorithm, value, source);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "issuer") {
        add_present_node(fields, JwtField::Issuer, value, source);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "audience") {
        add_present_node(fields, JwtField::Audience, value, source);
    }
    if let Some(options) = python_keyword_value(argument_nodes, source, "options") {
        add_python_options_fields(fields, source, options, option_aliases, line, column);
    }
    add_missing_for_verify_fields(fields, line, column);
}

fn add_python_options_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    node: Node<'_>,
    aliases: &BTreeMap<String, FieldSet>,
    line: usize,
    column: usize,
) {
    if is_dictionary(node) {
        if object_has_dynamic_spread(node, source) {
            for field in [JwtField::Issuer, JwtField::Audience, JwtField::Algorithm] {
                fields
                    .entry(field)
                    .or_insert_with(|| dynamic_field(field, line, column));
            }
        }
    } else if node.kind() == "identifier" {
        let alias_name = node_text(node, source);
        if let Some(alias) = aliases.get(&alias_name) {
            for field in [JwtField::Issuer, JwtField::Audience, JwtField::Algorithm] {
                if let Some(value) = alias.fields.get(&field) {
                    fields.entry(field).or_insert_with(|| value.clone());
                } else if alias.dynamic {
                    fields
                        .entry(field)
                        .or_insert_with(|| dynamic_field(field, line, column));
                }
            }
        } else {
            for field in [JwtField::Issuer, JwtField::Audience, JwtField::Algorithm] {
                fields
                    .entry(field)
                    .or_insert_with(|| dynamic_field(field, line, column));
            }
        }
    }
}

fn python_decode_disables_verification(
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &BTreeMap<String, FieldSet>,
) -> bool {
    let Some(options) = python_keyword_value(argument_nodes, source, "options") else {
        return false;
    };
    if is_dictionary(options) {
        return object_property_value(options, source, "verify_signature")
            .is_some_and(|value| is_false_literal(value, source));
    }
    if options.kind() == "identifier" {
        let alias_name = node_text(options, source);
        return option_aliases
            .get(&alias_name)
            .is_some_and(|alias| alias.fields.contains_key(&JwtField::Operation));
    }
    false
}

fn collect_js_imports(source: &str) -> JsImports {
    let mut imports = JsImports::default();
    imports.jsonwebtoken_namespaces.insert("jwt".to_string());

    for pattern in [
        r#"import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+["']jsonwebtoken["']"#,
        r#"import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+["']jsonwebtoken["']"#,
        r#"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*["']jsonwebtoken["']\s*\)"#,
    ] {
        let regex = Regex::new(pattern).expect("import regex should compile");
        for capture in regex.captures_iter(source) {
            imports
                .jsonwebtoken_namespaces
                .insert(capture[1].to_string());
        }
    }

    collect_js_named_imports(
        source,
        "jsonwebtoken",
        &mut imports.jsonwebtoken_functions,
        &["sign", "verify", "decode"],
    );
    collect_js_named_imports(
        source,
        "jose",
        &mut imports.jose_functions,
        &["jwtVerify", "decodeJwt", "SignJWT"],
    );
    imports
}

fn collect_js_named_imports(
    source: &str,
    package: &str,
    output: &mut BTreeMap<String, &'static str>,
    allowed: &[&'static str],
) {
    let import_regex = Regex::new(&format!(
        r#"import\s*\{{([^}}]+)\}}\s*from\s*["']{}["']"#,
        regex::escape(package)
    ))
    .expect("named import regex should compile");
    let require_regex = Regex::new(&format!(
        r#"(?:const|let|var)\s*\{{([^}}]+)\}}\s*=\s*require\s*\(\s*["']{}["']\s*\)"#,
        regex::escape(package)
    ))
    .expect("named require regex should compile");

    for capture in import_regex
        .captures_iter(source)
        .chain(require_regex.captures_iter(source))
    {
        for item in capture[1].split(',') {
            let item = item.trim();
            let mut pieces = item.split_whitespace().collect::<Vec<_>>();
            if pieces.len() == 3 && pieces[1] == "as" {
                let original = pieces.remove(0);
                let local = pieces.pop().expect("alias should exist");
                if let Some(allowed_original) = allowed.iter().find(|name| **name == original) {
                    output.insert(local.to_string(), *allowed_original);
                }
            } else if pieces.len() == 1 {
                let original = pieces[0];
                if let Some(allowed_original) = allowed.iter().find(|name| **name == original) {
                    output.insert(original.to_string(), *allowed_original);
                }
            }
        }
    }
}

fn collect_python_imports(source: &str) -> PyImports {
    let mut imports = PyImports::default();
    imports.jwt_modules.insert("jwt".to_string());

    let module_regex = Regex::new(r#"(?m)^\s*import\s+jwt(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?"#)
        .expect("python jwt import regex should compile");
    for capture in module_regex.captures_iter(source) {
        imports.jwt_modules.insert(
            capture
                .get(1)
                .map_or("jwt", |alias| alias.as_str())
                .to_string(),
        );
    }

    let fn_regex = Regex::new(r#"(?m)^\s*from\s+jwt\s+import\s+([A-Za-z0-9_,\sas]+)"#)
        .expect("python jwt function import regex should compile");
    for capture in fn_regex.captures_iter(source) {
        for item in capture[1].split(',') {
            let pieces = item.split_whitespace().collect::<Vec<_>>();
            if pieces.len() == 1 && matches!(pieces[0], "encode" | "decode") {
                let original: &'static str = if pieces[0] == "encode" {
                    "encode"
                } else {
                    "decode"
                };
                imports
                    .jwt_functions
                    .insert(pieces[0].to_string(), original);
            } else if pieces.len() == 3
                && pieces[1] == "as"
                && matches!(pieces[0], "encode" | "decode")
            {
                let original: &'static str = if pieces[0] == "encode" {
                    "encode"
                } else {
                    "decode"
                };
                imports
                    .jwt_functions
                    .insert(pieces[2].to_string(), original);
            }
        }
    }
    imports
}

fn collect_js_option_aliases(root: Node<'_>, source: &str) -> BTreeMap<String, FieldSet> {
    let mut aliases = BTreeMap::new();
    collect_option_aliases(root, source, &mut aliases, true);
    aliases
}

fn collect_python_option_aliases(root: Node<'_>, source: &str) -> BTreeMap<String, FieldSet> {
    let mut aliases = BTreeMap::new();
    collect_option_aliases(root, source, &mut aliases, false);
    aliases
}

fn collect_option_aliases(
    node: Node<'_>,
    source: &str,
    aliases: &mut BTreeMap<String, FieldSet>,
    javascript: bool,
) {
    if javascript && node.kind() == "variable_declarator" {
        if let (Some(name), Some(value)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        ) && is_object_literal(value)
        {
            aliases.insert(
                node_text(name, source),
                field_set_from_object(value, source),
            );
        }
    } else if !javascript && node.kind() == "assignment" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) && left.kind() == "identifier"
            && is_dictionary(right)
        {
            aliases.insert(
                node_text(left, source),
                field_set_from_object(right, source),
            );
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_option_aliases(child, source, aliases, javascript);
    }
}

fn field_set_from_object(node: Node<'_>, source: &str) -> FieldSet {
    let mut fields = BTreeMap::new();
    for (field, names) in [
        (JwtField::Algorithm, &["algorithm", "algorithms", "alg"][..]),
        (JwtField::Issuer, &["issuer", "iss"][..]),
        (JwtField::Audience, &["audience", "aud"][..]),
        (JwtField::Expiration, &["expiresIn", "expires", "exp"][..]),
    ] {
        add_object_field(&mut fields, field, node, source, names, 1, 1);
    }
    if object_property_value(node, source, "verify_signature")
        .is_some_and(|value| is_false_literal(value, source))
    {
        fields.insert(
            JwtField::Operation,
            JwtFieldEvidence {
                state: JwtAttributeState::Present,
                value: Some("decode_without_verify".to_string()),
                confidence: Confidence::High,
                line: node_line_column(node).0,
                column: node_line_column(node).1,
                excerpt: "verify_signature is false".into(),
            },
        );
    }
    FieldSet {
        fields,
        dynamic: object_has_dynamic_spread(node, source),
    }
}

fn add_object_field(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    object: Node<'_>,
    source: &str,
    names: &[&str],
    default_line: usize,
    default_column: usize,
) {
    for name in names {
        if let Some(value) = object_property_value(object, source, name) {
            add_present_node(fields, field, value, source);
            return;
        }
    }
    let (line, column) = if is_object_literal(object) || is_dictionary(object) {
        node_line_column(object)
    } else {
        (default_line, default_column)
    };
    if object_has_dynamic_spread(object, source) {
        fields
            .entry(field)
            .or_insert_with(|| dynamic_field(field, line, column));
    }
}

fn add_present_node(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    node: Node<'_>,
    source: &str,
) {
    let (line, column) = node_line_column(node);
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Present,
            value: Some(safe_node_value(node, source)),
            confidence: Confidence::High,
            line,
            column,
            excerpt: excerpt_for_node(source, node),
        },
    );
}

fn add_key_reference(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    node: Option<Node<'_>>,
    line: usize,
    column: usize,
) {
    match node {
        Some(node) => add_present_node(fields, JwtField::KeyReference, node, source),
        None => add_missing(fields, JwtField::KeyReference, line, column),
    }
}

fn add_missing_for_issue_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    line: usize,
    column: usize,
) {
    for field in [JwtField::Expiration] {
        if !fields.contains_key(&field) {
            add_missing(fields, field, line, column);
        }
    }
}

fn add_missing_for_verify_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    line: usize,
    column: usize,
) {
    for field in [JwtField::Issuer, JwtField::Audience] {
        if !fields.contains_key(&field) {
            add_missing(fields, field, line, column);
        }
    }
}

fn add_missing(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    line: usize,
    column: usize,
) {
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Missing,
            value: None,
            confidence: Confidence::High,
            line,
            column,
            excerpt: format!("{} is omitted", field.display_name()).into(),
        },
    );
}

fn dynamic_field(field: JwtField, line: usize, column: usize) -> JwtFieldEvidence {
    JwtFieldEvidence {
        state: JwtAttributeState::Dynamic,
        value: None,
        confidence: Confidence::Medium,
        line,
        column,
        excerpt: format!("{} depends on unresolved JWT options", field.display_name()).into(),
    }
}

fn add_regex_chain_field(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    text: &str,
    pattern: &str,
    line: usize,
    column: usize,
) {
    let regex = Regex::new(pattern).expect("chain regex should compile");
    if let Some(capture) = regex.captures(text) {
        fields.insert(
            field,
            JwtFieldEvidence {
                state: JwtAttributeState::Present,
                value: Some(safe_text_value(capture[1].trim())),
                confidence: Confidence::High,
                line,
                column,
                excerpt: SanitizedExcerpt(redact_excerpt(capture[0].trim())),
            },
        );
    }
}

fn is_jose_sign_chain(text: &str, imports: &JsImports) -> bool {
    imports.jose_functions.iter().any(|(local, original)| {
        *original == "SignJWT" && text.contains(&format!("new {local}")) && text.contains(".sign")
    })
}

fn infer_jwt_display_name(
    function_name: Option<&str>,
    call: Node<'_>,
    source: &str,
) -> Option<String> {
    let mut candidates = Vec::new();
    if let Some(function_name) = function_name {
        candidates.push(function_name.to_string());
    }
    if let Some(name) = assignment_name_for_call(call, source) {
        candidates.push(name);
    }
    candidates.push(node_text(call, source));

    let joined = candidates.join(" ").to_ascii_lowercase();
    if joined.contains("refresh") {
        Some("refresh_jwt".to_string())
    } else if joined.contains("legacy") {
        Some("legacy_access_jwt".to_string())
    } else if [
        "access",
        "session",
        "auth",
        "current_user",
        "currentuser",
        "bearer",
    ]
    .iter()
    .any(|needle| joined.contains(needle))
    {
        Some("access_jwt".to_string())
    } else {
        None
    }
}

fn artifact_type_for_name(name: Option<&str>) -> ArtifactType {
    match name.unwrap_or_default() {
        "access_jwt" | "legacy_access_jwt" => ArtifactType::AccessJwt,
        "refresh_jwt" => ArtifactType::RefreshJwt,
        _ => ArtifactType::Unknown,
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
        ArtifactType::PasswordResetToken => "password_reset_token",
        ArtifactType::EmailVerificationToken => "email_verification_token",
        ArtifactType::SessionRecord => "session_record",
        ArtifactType::Unknown => "unknown",
    }
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

fn jwt_state_part(state: JwtAttributeState) -> &'static str {
    match state {
        JwtAttributeState::Present => "present",
        JwtAttributeState::Missing => "missing",
        JwtAttributeState::Dynamic => "dynamic",
        JwtAttributeState::Unknown => "unknown",
    }
}

fn object_property_value<'tree>(
    node: Node<'tree>,
    source: &str,
    property_name: &str,
) -> Option<Node<'tree>> {
    if !is_object_literal(node) && !is_dictionary(node) {
        return None;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some((key, value)) = object_pair(child)
            && property_key_text(key, source).as_deref() == Some(property_name)
        {
            return Some(value);
        }
    }
    None
}

fn object_pair(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    match node.kind() {
        "pair" => Some((
            node.child_by_field_name("key")?,
            node.child_by_field_name("value")?,
        )),
        "shorthand_property_identifier_pattern" | "shorthand_property_identifier" => {
            Some((node, node))
        }
        _ => None,
    }
}

fn property_key_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "property_identifier" | "identifier" => Some(node_text(node, source)),
        "string" => parse_string_text(&node_text(node, source)),
        _ => Some(node_text(node, source)),
    }
}

fn object_has_dynamic_spread(node: Node<'_>, source: &str) -> bool {
    let text = node_text(node, source);
    text.contains("...") || text.contains("**")
}

fn is_object_literal(node: Node<'_>) -> bool {
    matches!(node.kind(), "object" | "object_pattern")
}

fn is_dictionary(node: Node<'_>) -> bool {
    matches!(node.kind(), "dictionary" | "dictionary_pattern")
}

fn is_member_expression(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "member_expression" | "optional_chain" | "subscript_expression"
    )
}

fn python_keyword_value<'tree>(
    argument_nodes: &[Node<'tree>],
    source: &str,
    keyword: &str,
) -> Option<Node<'tree>> {
    for argument in argument_nodes {
        if argument.kind() == "keyword_argument"
            && let Some(name) = argument.child_by_field_name("name")
            && node_text(name, source) == keyword
        {
            return argument.child_by_field_name("value").or_else(|| {
                argument
                    .named_child_count()
                    .checked_sub(1)
                    .and_then(|index| argument.named_child(index as u32))
            });
        }
    }
    None
}

fn is_false_literal(node: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(node, source).to_ascii_lowercase().as_str(),
        "false" | "False"
    )
}

fn safe_node_value(node: Node<'_>, source: &str) -> String {
    safe_text_value(&node_text(node, source))
}

fn safe_text_value(text: &str) -> String {
    let trimmed = text.trim();
    if parse_string_text(trimmed).is_some() || trimmed.starts_with('[') || trimmed.starts_with('{')
    {
        "[literal]".to_string()
    } else {
        trimmed
            .chars()
            .take(80)
            .collect::<String>()
            .replace(['\n', '\r', '\t'], " ")
    }
}

fn js_function_name(node: Node<'_>, source: &str) -> Option<String> {
    if matches!(
        node.kind(),
        "function_declaration" | "function" | "method_definition"
    ) {
        return node
            .child_by_field_name("name")
            .map(|name| node_text(name, source));
    }
    None
}

fn python_function_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "function_definition" {
        return node
            .child_by_field_name("name")
            .map(|name| node_text(name, source));
    }
    None
}

fn assignment_name_for_call(call: Node<'_>, source: &str) -> Option<String> {
    let mut current = call.parent();
    while let Some(node) = current {
        if node.kind() == "variable_declarator" || node.kind() == "assignment" {
            return node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("left"))
                .map(|name| node_text(name, source));
        }
        if matches!(
            node.kind(),
            "function_declaration" | "function_definition" | "statement_block" | "block"
        ) {
            break;
        }
        current = node.parent();
    }
    None
}

fn node_line_column(node: Node<'_>) -> (usize, usize) {
    let position = node.start_position();
    (position.row + 1, position.column + 1)
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn excerpt_for_node(source: &str, node: Node<'_>) -> SanitizedExcerpt {
    let text = node_text(node, source);
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let excerpt = if collapsed.len() > 240 {
        format!("{}...", &collapsed[..240])
    } else {
        collapsed
    };
    SanitizedExcerpt(redact_excerpt(&excerpt))
}

fn redact_excerpt(text: &str) -> String {
    let mut output = PLACEHOLDER_SECRET_RE
        .replace_all(text, REDACTION)
        .to_string();
    output = JWT_RE.replace_all(&output, REDACTION).to_string();
    output = LONG_LITERAL_RE
        .replace_all(&output, |captures: &regex::Captures<'_>| {
            let left = captures
                .get(0)
                .map(|matched| matched.as_str())
                .unwrap_or_default()
                .split(['"', '\''])
                .next()
                .unwrap_or_default();
            format!("{left}\"{REDACTION}\"")
        })
        .to_string();
    output
}

fn parse_string_text(text: &str) -> Option<String> {
    let mut chars = text.chars();
    let quote = chars.next()?;
    if !matches!(quote, '"' | '\'' | '`') || !text.ends_with(quote) || text.len() < 2 {
        return None;
    }
    Some(text[quote.len_utf8()..text.len() - quote.len_utf8()].to_string())
}

fn node_text(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes())
        .expect("tree-sitter node should be valid UTF-8")
        .to_string()
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{ArtifactType, Language};

    use super::*;

    fn detect(language: Language, source: &str) -> DetectionOutput {
        JwtDetector.detect(&DetectorInput {
            path: match language {
                Language::Python => "auth.py",
                _ => "auth.ts",
            },
            language,
            source,
        })
    }

    #[test]
    fn detects_jsonwebtoken_sign_and_verify() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
const ISSUER = "issuer";
const AUDIENCE = "aud";
export function issueAccessJwt(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { issuer: ISSUER, audience: AUDIENCE, expiresIn: "15m" });
}
export function verifyAccessJwt(token: string) {
  return jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: AUDIENCE });
}
"#,
        );

        let artifact = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT artifact should exist");
        assert_eq!(artifact.artifact_type, ArtifactType::AccessJwt);
        assert!(!artifact.lifecycle_evidence.issue.is_empty());
        assert!(!artifact.lifecycle_evidence.validate.is_empty());
        assert!(!artifact.lifecycle_evidence.expire.is_empty());
        let attributes = artifact.jwt_attributes.as_ref().expect("jwt attributes");
        assert_eq!(attributes.issuer.state, JwtAttributeState::Present);
        assert_eq!(attributes.audience.state, JwtAttributeState::Present);
        assert_eq!(attributes.expiration.state, JwtAttributeState::Present);
        assert!(!detected_text(&output).contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    }

    #[test]
    fn detects_jsonwebtoken_decode_without_verify() {
        let output = detect(
            Language::TypeScript,
            r#"
import { decode } from "jsonwebtoken";
export function inspectAccessJwt(token: string) {
  return decode(token);
}
"#,
        );

        let artifact = &output.artifacts[0];
        assert!(!artifact.lifecycle_evidence.introspect.is_empty());
        assert_eq!(
            artifact
                .jwt_attributes
                .as_ref()
                .expect("jwt attributes")
                .operation
                .value
                .as_deref(),
            Some("decode_without_verify")
        );
    }

    #[test]
    fn detects_jose_sign_and_verify() {
        let output = detect(
            Language::TypeScript,
            r#"
import { jwtVerify, SignJWT } from "jose";
const secret = new TextEncoder().encode("PLACEHOLDER_SECRET_DO_NOT_USE");
export async function issueAccessJwt() {
  return await new SignJWT({ sub: "user" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime("15m")
    .sign(secret);
}
export async function verifyAccessJwt(token: string) {
  return jwtVerify(token, secret, { issuer, audience });
}
"#,
        );

        let artifact = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT artifact should exist");
        assert!(artifact.framework_hints.contains(&"jose".to_string()));
        assert!(!artifact.lifecycle_evidence.issue.is_empty());
        assert!(!artifact.lifecycle_evidence.validate.is_empty());
    }

    #[test]
    fn detects_pyjwt_encode_decode_and_decode_without_verify() {
        let output = detect(
            Language::Python,
            r#"
import jwt as pyjwt
JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE"

def issue_access_jwt(user_id):
    return pyjwt.encode({"sub": user_id, "iss": ISSUER, "aud": AUDIENCE, "exp": expires_at}, JWT_SECRET, algorithm="HS256")

def verify_legacy_jwt(token):
    return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])

def inspect_access_jwt(token):
    return pyjwt.decode(token, options={"verify_signature": False})
"#,
        );

        assert!(output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("access_jwt")
                && !artifact.lifecycle_evidence.issue.is_empty()
        }));
        assert!(output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("legacy_access_jwt")
                && artifact
                    .jwt_attributes
                    .as_ref()
                    .is_some_and(|attributes| attributes.issuer.state == JwtAttributeState::Missing)
        }));
        assert!(
            output
                .artifacts
                .iter()
                .any(|artifact| !artifact.lifecycle_evidence.introspect.is_empty())
        );
        assert!(!detected_text(&output).contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    }

    #[test]
    fn ignores_comments_and_strings() {
        let output = detect(
            Language::TypeScript,
            r#"
// jwt.verify(token, secret)
const text = "jwt.sign(payload, secret)";
"#,
        );

        assert!(output.artifacts.is_empty());
        assert!(output.evidence.is_empty());
    }

    fn detected_text(output: &DetectionOutput) -> String {
        let excerpts = output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.0.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let values = output
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.jwt_attributes.as_ref())
            .flat_map(|attributes| {
                [
                    &attributes.operation,
                    &attributes.algorithm,
                    &attributes.key_reference,
                    &attributes.issuer,
                    &attributes.audience,
                    &attributes.expiration,
                ]
            })
            .filter_map(|observation| observation.value.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        format!("{excerpts}\n{values}")
    }
}
