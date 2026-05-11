use std::collections::BTreeMap;

use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, Language, LifecycleEvidence, LifecycleStage,
    SanitizedExcerpt, SourceLocation, stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "cookie.set";

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Wrapper {
    name: String,
    cookie_name_parameter_index: usize,
}

fn detect_javascript_like(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_javascript_like(input, input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let wrappers = collect_js_wrappers(root, input.source);
    let mut calls = Vec::new();
    collect_js_cookie_calls(root, input.source, &[], &mut calls);
    collect_js_wrapper_calls(root, input.source, &wrappers, &mut calls);

    calls_to_output(input, detector_id, calls)
}

fn detect_python(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let wrappers = collect_python_wrappers(root, input.source);
    let mut calls = Vec::new();
    collect_python_cookie_calls(root, input.source, &[], &mut calls);
    collect_python_wrapper_calls(root, input.source, &wrappers, &mut calls);

    calls_to_output(input, detector_id, calls)
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

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type,
            display_name: call.cookie_name,
            locations: vec![location.clone()],
            lifecycle_evidence: LifecycleEvidence {
                store: vec![evidence_id.clone()],
                ..LifecycleEvidence::default()
            },
            confidence,
            framework_hints: vec![call.framework_hint.to_string()],
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
    }

    output
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

fn excerpt_around_node(source: &str, node: Node<'_>) -> SanitizedExcerpt {
    let target_line = node.start_position().row;
    let lines = source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return SanitizedExcerpt(String::new());
    }

    let start = target_line.saturating_sub(1);
    let end = (target_line + 2).min(lines.len());
    SanitizedExcerpt(lines[start..end].join("\n"))
}

fn collect_js_cookie_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    calls: &mut Vec<CookieCall>,
) {
    if is_function_node(node) {
        let parameters = function_parameters_for_js_function(node, source);
        collect_js_children(node, source, &parameters, calls);
        return;
    }

    if node.kind() == "call_expression"
        && let Some(call) = js_cookie_call(node, source, function_parameters)
    {
        calls.push(call);
    }

    collect_js_children(node, source, function_parameters, calls);
}

fn collect_js_children<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    calls: &mut Vec<CookieCall>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_cookie_calls(child, source, function_parameters, calls);
    }
}

fn collect_python_cookie_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
    calls: &mut Vec<CookieCall>,
) {
    if node.kind() == "function_definition" {
        let parameters = function_parameters_for_python_function(node, source);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_python_cookie_calls(child, source, &parameters, calls);
        }
        return;
    }

    if node.kind() == "call"
        && let Some(call) = python_cookie_call(node, source, function_parameters)
    {
        calls.push(call);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_cookie_calls(child, source, function_parameters, calls);
    }
}

fn js_cookie_call<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
) -> Option<CookieCall> {
    let function = node.child_by_field_name("function")?;
    let (api_name, framework_hint) = js_supported_cookie_api(function, source)?;
    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let name_argument = argument_nodes.first().copied()?;

    if is_identifier_in_parameters(name_argument, source, function_parameters) {
        return None;
    }

    Some(CookieCall {
        api_name,
        framework_hint,
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node(source, node),
        cookie_name: string_literal_value(name_argument, source),
        signed: argument_nodes
            .get(2)
            .is_some_and(|options| object_has_signed_true(*options, source)),
    })
}

fn python_cookie_call<'tree>(
    node: Node<'tree>,
    source: &str,
    function_parameters: &[String],
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

    Some(CookieCall {
        api_name: "python.set_cookie",
        framework_hint: "python",
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node(source, node),
        cookie_name: string_literal_value(name_argument, source),
        signed: false,
    })
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

fn collect_js_wrappers(root: Node<'_>, source: &str) -> BTreeMap<String, Wrapper> {
    let mut wrappers = BTreeMap::new();
    collect_js_wrappers_from_node(root, source, &mut wrappers);
    wrappers
}

fn collect_js_wrappers_from_node(
    node: Node<'_>,
    source: &str,
    wrappers: &mut BTreeMap<String, Wrapper>,
) {
    if is_function_node(node)
        && let Some(wrapper) = js_wrapper(node, source)
    {
        wrappers.insert(wrapper.name.clone(), wrapper);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_wrappers_from_node(child, source, wrappers);
    }
}

fn js_wrapper(node: Node<'_>, source: &str) -> Option<Wrapper> {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .or_else(|| js_variable_function_name(node, source))?;
    let parameters = function_parameters_for_js_function(node, source);
    if parameters.is_empty() {
        return None;
    }

    let cookie_name_parameter_index =
        find_js_cookie_name_parameter_index(node, source, &parameters)?;
    Some(Wrapper {
        name,
        cookie_name_parameter_index,
    })
}

fn find_js_cookie_name_parameter_index(
    node: Node<'_>,
    source: &str,
    parameters: &[String],
) -> Option<usize> {
    if node.kind() == "call_expression" {
        let function = node.child_by_field_name("function")?;
        js_supported_cookie_api(function, source)?;
        let arguments = node.child_by_field_name("arguments")?;
        let name_argument = named_children(arguments).first().copied()?;
        return parameters
            .iter()
            .position(|parameter| node_text(name_argument, source) == *parameter);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(index) = find_js_cookie_name_parameter_index(child, source, parameters) {
            return Some(index);
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
        api_name: "javascript.wrapper.cookie",
        framework_hint: "wrapper",
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node(source, node),
        cookie_name: Some(cookie_name),
        signed: false,
    })
}

fn collect_python_wrappers(root: Node<'_>, source: &str) -> BTreeMap<String, Wrapper> {
    let mut wrappers = BTreeMap::new();
    collect_python_wrappers_from_node(root, source, &mut wrappers);
    wrappers
}

fn collect_python_wrappers_from_node(
    node: Node<'_>,
    source: &str,
    wrappers: &mut BTreeMap<String, Wrapper>,
) {
    if node.kind() == "function_definition"
        && let Some(wrapper) = python_wrapper(node, source)
    {
        wrappers.insert(wrapper.name.clone(), wrapper);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_wrappers_from_node(child, source, wrappers);
    }
}

fn python_wrapper(node: Node<'_>, source: &str) -> Option<Wrapper> {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source))?;
    let parameters = function_parameters_for_python_function(node, source);
    if parameters.is_empty() {
        return None;
    }

    let cookie_name_parameter_index =
        find_python_cookie_name_parameter_index(node, source, &parameters)?;
    Some(Wrapper {
        name,
        cookie_name_parameter_index,
    })
}

fn find_python_cookie_name_parameter_index(
    node: Node<'_>,
    source: &str,
    parameters: &[String],
) -> Option<usize> {
    if node.kind() == "call" {
        let function = node.child_by_field_name("function")?;
        if !python_supported_cookie_api(function, source) {
            return None;
        }
        let arguments = node.child_by_field_name("arguments")?;
        let name_argument = first_python_cookie_name_argument(&named_children(arguments), source)?;
        return parameters
            .iter()
            .position(|parameter| node_text(name_argument, source) == *parameter);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(index) = find_python_cookie_name_parameter_index(child, source, parameters) {
            return Some(index);
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
        api_name: "python.wrapper.set_cookie",
        framework_hint: "wrapper",
        line: node_line_column(node).0,
        column: node_line_column(node).1,
        excerpt: excerpt_around_node(source, node),
        cookie_name: Some(cookie_name),
        signed: false,
    })
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

#[cfg(test)]
mod tests {
    use sessionscope_model::{ArtifactType, Confidence, Language};

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
        assert_eq!(output.evidence.len(), 1);
        assert_eq!(
            output.artifacts[0].artifact_type,
            ArtifactType::SignedCookie
        );
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert_eq!(output.artifacts[0].confidence, Confidence::High);
        assert_eq!(output.artifacts[0].locations[0].line, Some(1));
        assert_eq!(output.artifacts[0].locations[0].column, Some(1));
        assert_eq!(
            output.artifacts[0].lifecycle_evidence.store,
            vec![output.evidence[0].id.clone()]
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
  response.cookie(name, value, { httpOnly: true });
}

setAuthCookie(response, "session", token);
"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert_eq!(output.artifacts[0].framework_hints, vec!["wrapper"]);
    }

    #[test]
    fn detects_simple_python_wrapper_calls() {
        let output = detect(
            Language::Python,
            r#"
def set_auth_cookie(response, name, value):
    response.set_cookie(name, value, httponly=True)

set_auth_cookie(response, "session", token)
"#,
        );

        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].display_name.as_deref(), Some("session"));
        assert_eq!(output.artifacts[0].framework_hints, vec!["wrapper"]);
    }
}
