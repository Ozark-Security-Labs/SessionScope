use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, EvidenceId, Language, LifecycleEvidence,
    LifecycleStage, SanitizedExcerpt, SourceLocation, stable_artifact_id, stable_evidence_id,
};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "oauth.flow";
const REDACTION: &str = "[REDACTED]";

static OAUTH_FLOW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(OAuth2Strategy|authorizationUrl|authorization_url|OAuthProvider|OIDCProvider|register\(|authorize_redirect|response_type\s*[:=]\s*['\"]code)"#)
        .expect("oauth flow regex should compile")
});
static PKCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(code_challenge|codeChallenge|code_verifier|codeVerifier|code_challenge_method|S256|checks\s*[:=][^\n]*(pkce))")
        .expect("pkce regex should compile")
});
static STATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bstate\b").expect("state regex should compile"));
static STATIC_STATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)\bstate\b\s*[:=]\s*(?:"[A-Za-z0-9._~+/-]{4,}"|'[A-Za-z0-9._~+/-]{4,}')"#)
        .expect("static state regex should compile")
});
static STATE_VERIFY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(state[^\n]{0,80}(===|==|!=|!==)[^\n]{0,80}(session|cookie|cache|expected|csrf)|(session|cookie|cache|expected|csrf)[^\n]{0,80}state[^\n]{0,80}(===|==|!=|!==)[^\n]{0,80}state|compare_digest\([^\n]*state)")
        .expect("state verification regex should compile")
});
static OPENID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(scope\s*[:=][^\n]*openid|\bopenid\b|OIDCProvider)")
        .expect("openid regex should compile")
});
static NONCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bnonce\b").expect("nonce regex should compile"));
static NONCE_VERIFY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)((verifyIdToken|verify_id_token|parse_id_token|jwtVerify)[^\n]{0,80}nonce|nonce[^\n]{0,80}(===|==|!=|!==)[^\n]{0,80}(expected|session|cookie|cache)|id_token[^\n]{0,80}nonce[^\n]{0,80}(===|==|!=|!==)[^\n]{0,80}(expected|session|cookie|cache))",
    )
    .expect("nonce verification regex should compile")
});
static REDIRECT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)\bredirect_?uris?\b\s*[:=]\s*(\[[^\n\]]+\]|["'][^"']+["'])"#)
        .expect("redirect uri regex should compile")
});
static QUOTED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']([^"']+)["']"#).expect("quoted regex should compile"));
static OAUTH_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?ix)(\b(?:state|nonce|code_verifier|codeVerifier|code_challenge|codeChallenge)\b\s*[:=]\s*)(["'`])([^"'`]{8,})(["'`])"#)
        .expect("oauth value regex should compile")
});
static OAUTH_URL_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([?&#](?:state|nonce|code_verifier|code_challenge)=)([^&#\s"']+)"#)
        .expect("oauth url value regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct OAuthFlowDetector;

impl Detector for OAuthFlowDetector {
    fn id(&self) -> &'static str {
        DETECTOR_ID
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        match input.language {
            Language::JavaScript | Language::TypeScript | Language::Python => detect(input),
            _ => DetectionOutput::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct Signal {
    detector_id: &'static str,
    stage: LifecycleStage,
    line: usize,
    column: usize,
    confidence: Confidence,
    dynamic: bool,
    framework_default: bool,
    excerpt: SanitizedExcerpt,
}

fn detect(input: &DetectorInput<'_>) -> DetectionOutput {
    let mut signals = Vec::new();
    let mut saw_flow = false;

    for (index, line) in input.source.lines().enumerate() {
        let line_number = index + 1;
        if OAUTH_FLOW_RE.is_match(line) && !is_import_only_line(line) {
            saw_flow = true;
            signals.push(signal(
                "oauth.flow.auth_code",
                LifecycleStage::Issue,
                line,
                line_number,
                false,
                false,
            ));
            if line.to_ascii_lowercase().contains("nextauth")
                || line.contains("OAuthProvider")
                || line.contains("OIDCProvider")
            {
                signals.push(signal(
                    "oauth.flow.framework_default",
                    LifecycleStage::Issue,
                    line,
                    line_number,
                    true,
                    true,
                ));
            }
        }
        if PKCE_RE.is_match(line) {
            signals.push(signal(
                "oauth.pkce.present",
                LifecycleStage::Issue,
                line,
                line_number,
                false,
                false,
            ));
        }
        if STATE_RE.is_match(line) {
            let detector_id = if STATIC_STATE_RE.is_match(line) {
                "oauth.state.static"
            } else if line.to_ascii_lowercase().contains("req.query")
                || line.to_ascii_lowercase().contains("request.query")
                || line.to_ascii_lowercase().contains("searchparams")
            {
                "oauth.state.callback_read"
            } else {
                "oauth.state.present"
            };
            signals.push(signal(
                detector_id,
                LifecycleStage::Validate,
                line,
                line_number,
                !STATIC_STATE_RE.is_match(line),
                false,
            ));
        }
        if STATE_VERIFY_RE.is_match(line) {
            signals.push(signal(
                "oauth.state.verified",
                LifecycleStage::Validate,
                line,
                line_number,
                false,
                false,
            ));
        }
        if OPENID_RE.is_match(line) {
            signals.push(signal(
                "oauth.oidc.openid_scope",
                LifecycleStage::Issue,
                line,
                line_number,
                false,
                false,
            ));
        }
        if NONCE_RE.is_match(line) {
            signals.push(signal(
                "oauth.nonce.present",
                LifecycleStage::Issue,
                line,
                line_number,
                true,
                false,
            ));
        }
        if NONCE_VERIFY_RE.is_match(line) {
            signals.push(signal(
                "oauth.nonce.verified",
                LifecycleStage::Validate,
                line,
                line_number,
                false,
                false,
            ));
        }
        if REDIRECT_RE.is_match(line) {
            signals.push(signal(
                "oauth.redirect_uri.literal",
                LifecycleStage::Issue,
                line,
                line_number,
                false,
                false,
            ));
            if redirect_line_is_broad(line) {
                signals.push(signal(
                    "oauth.redirect_uri.broad",
                    LifecycleStage::Issue,
                    line,
                    line_number,
                    false,
                    false,
                ));
            }
        }
    }

    if !saw_flow
        && !signals
            .iter()
            .any(|signal| signal.detector_id == "oauth.flow.auth_code")
    {
        return DetectionOutput::default();
    }

    signals_to_output(input, signals)
}

fn signal(
    detector_id: &'static str,
    stage: LifecycleStage,
    line: &str,
    line_number: usize,
    dynamic: bool,
    framework_default: bool,
) -> Signal {
    Signal {
        detector_id,
        stage,
        line: line_number,
        column: 1,
        confidence: if dynamic {
            Confidence::Medium
        } else {
            Confidence::High
        },
        dynamic,
        framework_default,
        excerpt: SanitizedExcerpt::from_sanitized(sanitize_oauth_excerpt(line)),
    }
}

fn signals_to_output(input: &DetectorInput<'_>, signals: Vec<Signal>) -> DetectionOutput {
    let mut output = DetectionOutput::default();
    let flow_lines = signals
        .iter()
        .filter(|signal| signal.detector_id == "oauth.flow.auth_code")
        .map(|signal| signal.line)
        .collect::<Vec<_>>();

    for (index, flow_line) in flow_lines.iter().copied().enumerate() {
        let next_flow_line = flow_lines.get(index + 1).copied();
        let artifact_id = stable_artifact_id(&[
            DETECTOR_ID,
            "oauth_auth_code_flow",
            input.path,
            flow_line.to_string().as_str(),
        ]);
        let mut lifecycle_evidence = LifecycleEvidence::default();
        let mut evidence = Vec::new();

        for signal in signals
            .iter()
            .filter(|signal| signal_belongs_to_flow(signal, flow_line, next_flow_line))
        {
            let line = signal.line.to_string();
            let column = signal.column.to_string();
            let evidence_id = stable_evidence_id(&[
                DETECTOR_ID,
                signal.detector_id,
                input.path,
                line.as_str(),
                column.as_str(),
                flow_line.to_string().as_str(),
            ]);
            push_lifecycle_id(&mut lifecycle_evidence, signal.stage, evidence_id.clone());
            evidence.push(Evidence {
                id: evidence_id,
                lifecycle_stage: signal.stage,
                location: SourceLocation {
                    path: input.path.to_string(),
                    line: Some(signal.line),
                    column: Some(signal.column),
                },
                detector_id: signal.detector_id.to_string(),
                confidence: signal.confidence,
                excerpt: Some(signal.excerpt.clone()),
                dynamic: signal.dynamic,
                framework_default: signal.framework_default,
            });
        }

        if evidence.is_empty() {
            continue;
        }

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type: ArtifactType::OAuthAuthCodeFlow,
            display_name: Some(format!("oauth_auth_code_flow:{flow_line}")),
            locations: vec![SourceLocation {
                path: input.path.to_string(),
                line: Some(flow_line),
                column: Some(1),
            }],
            lifecycle_evidence,
            confidence: Confidence::High,
            framework_hints: framework_hints(input.path, input.source),
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        });
        output.evidence.extend(evidence);
    }
    output
}

fn signal_belongs_to_flow(
    signal: &Signal,
    flow_line: usize,
    next_flow_line: Option<usize>,
) -> bool {
    if signal.detector_id == "oauth.flow.auth_code" {
        return signal.line == flow_line;
    }
    signal.line >= flow_line
        && signal.line <= flow_line + 8
        && next_flow_line.is_none_or(|next| signal.line < next)
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
    if !bucket.contains(&id) {
        bucket.push(id);
    }
}

fn framework_hints(path: &str, source: &str) -> Vec<String> {
    let haystack = format!(
        "{}\n{}",
        path.to_ascii_lowercase(),
        source.to_ascii_lowercase()
    );
    let mut hints = Vec::new();
    for (needle, hint) in [
        ("passport", "passport-oauth2"),
        ("openid-client", "openid-client"),
        ("nextauth", "next-auth"),
        ("authjs", "next-auth"),
        ("authlib", "authlib"),
        ("oauth2session", "authlib"),
        ("oauth2client", "authlib"),
    ] {
        if haystack.contains(needle) && !hints.iter().any(|existing| existing == hint) {
            hints.push(hint.to_string());
        }
    }
    if hints.is_empty() {
        hints.push("oauth-generic".to_string());
    }
    hints
}

fn is_import_only_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("import ") || trimmed.starts_with("from ")
}

fn redirect_line_is_broad(line: &str) -> bool {
    QUOTED_RE.captures_iter(line).any(|capture| {
        let value = capture.get(1).map_or("", |capture| capture.as_str());
        if is_loopback_redirect(value) {
            return false;
        }
        value.contains('*') || bare_host(value) || top_level_wildcard(value)
    })
}

fn is_loopback_redirect(value: &str) -> bool {
    value.contains("localhost") || value.contains("127.0.0.1") || value.contains("[::1]")
}

fn bare_host(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    !rest.contains('/') || rest.ends_with('/')
}

fn top_level_wildcard(value: &str) -> bool {
    value.starts_with("*.") || value.contains("://*.")
}

fn sanitize_oauth_excerpt(line: &str) -> String {
    let mut output = OAUTH_VALUE_RE
        .replace_all(line, format!("${{1}}${{2}}{REDACTION}${{4}}"))
        .to_string();
    output = OAUTH_URL_VALUE_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(source: &str) -> DetectorInput<'_> {
        DetectorInput {
            path: "src/auth.ts",
            source,
            language: Language::TypeScript,
        }
    }

    #[test]
    fn detects_auth_code_flow_with_pkce_state_and_redirect_evidence() {
        let output = OAuthFlowDetector.detect(&input(
            r#"
const url = client.authorizationUrl({ response_type: 'code', scope: 'openid profile', state: crypto.randomUUID(), code_challenge: challenge, redirect_uris: ['https://*.example.com'] });
if (req.query.state === session.oauthState) {}
verifyIdToken(token, { nonce })
"#,
        ));

        assert!(
            output
                .artifacts
                .iter()
                .any(|artifact| artifact.artifact_type == ArtifactType::OAuthAuthCodeFlow)
        );
        for detector_id in [
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
            "oauth.oidc.openid_scope",
            "oauth.nonce.present",
            "oauth.nonce.verified",
            "oauth.redirect_uri.broad",
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
    fn redacts_oauth_high_entropy_values_in_excerpts() {
        let output = OAuthFlowDetector.detect(&input(
            "client.authorizationUrl({ response_type: 'code', state: `abcdefghijklmnopqrstuvwxyz123456`, nonce: 'ZYXWVUTSRQPONMLKJIHGFEDCBA987654' })",
        ));
        let rendered = format!("{:?}", output.evidence);
        assert!(!rendered.contains("abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!rendered.contains("ZYXWVUTSRQPONMLKJIHGFEDCBA987654"));
    }

    #[test]
    fn suppresses_loopback_bare_redirect_review() {
        assert!(!redirect_line_is_broad(
            "redirect_uris: ['http://localhost:3000']"
        ));
        assert!(redirect_line_is_broad(
            "redirect_uris: ['https://example.com']"
        ));
    }

    #[test]
    fn does_not_mark_state_or_nonce_reads_as_verification() {
        let output = OAuthFlowDetector.detect(&input(
            r#"
const url = client.authorizationUrl({ response_type: 'code', scope: 'openid', state, nonce, code_challenge: challenge })
const callbackState = req.query.state
const expectedState = session.oauthState
const idNonce = id_token.nonce
"#,
        ));

        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "oauth.state.verified")
        );
        assert!(
            !output
                .evidence
                .iter()
                .any(|evidence| evidence.detector_id == "oauth.nonce.verified")
        );
    }

    #[test]
    fn creates_separate_artifacts_for_separate_flows() {
        let output = OAuthFlowDetector.detect(&input(
            r#"
const good = client.authorizationUrl({ response_type: 'code', state, code_challenge: challenge })
const farAway = true
const otherFarAway = true
const another = true
const unsafe = client.authorizationUrl({ response_type: 'code' })
"#,
        ));

        assert_eq!(output.artifacts.len(), 2);
    }
}
