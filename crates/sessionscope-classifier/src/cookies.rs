use std::net::IpAddr;

use sessionscope_model::{
    Artifact, ArtifactType, Confidence, CookieAttributeObservation, CookieAttributeState,
    EvidenceId, Finding, FindingCategory, ScanReport, Severity, stable_finding_id,
};

const EXCESSIVE_COOKIE_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for artifact in &report.artifacts {
        let Some(attributes) = &artifact.cookie_attributes else {
            continue;
        };

        let cookie_name = artifact.display_name.as_deref().unwrap_or("unknown cookie");
        let session_like = is_session_like_cookie(artifact);
        let has_static_name = artifact.display_name.is_some();

        if session_like {
            findings.extend(classify_http_only(
                artifact,
                cookie_name,
                &attributes.http_only,
            ));
        }

        if has_static_name {
            findings.extend(classify_secure(artifact, cookie_name, &attributes.secure));
        }

        findings.extend(classify_same_site_none_without_secure(
            artifact,
            cookie_name,
            &attributes.same_site,
            &attributes.secure,
        ));
        findings.extend(classify_same_site_posture(
            artifact,
            cookie_name,
            &attributes.same_site,
            &attributes.secure,
            session_like,
        ));
        findings.extend(classify_lifetime_posture(
            artifact,
            cookie_name,
            &attributes.max_age,
            &attributes.expires,
        ));
        findings.extend(classify_scope_posture(
            artifact,
            cookie_name,
            &attributes.path,
            &attributes.domain,
            session_like,
        ));

        if session_like || artifact.artifact_type == ArtifactType::SignedCookie {
            findings.extend(classify_expiry(
                artifact,
                cookie_name,
                &attributes.max_age,
                &attributes.expires,
            ));
        }
    }

    findings
}

fn classify_http_only(
    artifact: &Artifact,
    cookie_name: &str,
    http_only: &CookieAttributeObservation,
) -> Option<Finding> {
    match http_only.state {
        CookieAttributeState::Missing if http_only.confidence == Confidence::High => {
            Some(finding(
                "cookie_missing_httponly",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                http_only.evidence_ids.clone(),
                format!("Session-like cookie `{cookie_name}` does not set HttpOnly"),
                "No HttpOnly attribute evidence was detected for this cookie-setting call."
                    .to_string(),
                "Set HttpOnly on session cookies so client-side scripts cannot read them."
                    .to_string(),
                "Is this cookie intended to be inaccessible to browser JavaScript?".to_string(),
            ))
        }
        CookieAttributeState::FrameworkDefault
            if observation_value_is_false(http_only) && http_only.confidence == Confidence::Low =>
        {
            Some(finding(
                "cookie_default_false_httponly",
                FindingCategory::FrameworkDefaultAssumed,
                Severity::Low,
                artifact,
                http_only.evidence_ids.clone(),
                format!("Session-like cookie `{cookie_name}` defaults HttpOnly to false"),
                "Framework default evidence indicates HttpOnly is false for this cookie-setting call."
                    .to_string(),
                "Set HttpOnly explicitly on session cookies so client-side scripts cannot read them."
                    .to_string(),
                "Which framework version and deployment settings determine HttpOnly here?"
                    .to_string(),
            ))
        }
        CookieAttributeState::Dynamic => Some(finding(
            "cookie_dynamic_httponly",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            http_only.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` has dynamic HttpOnly evidence"),
            "The HttpOnly attribute appears to depend on a non-literal expression."
                .to_string(),
            "Confirm the effective production value and set HttpOnly explicitly when possible."
                .to_string(),
            "Can production guarantee HttpOnly is enabled for this cookie?".to_string(),
        )),
        CookieAttributeState::FrameworkDefault => Some(finding(
            "cookie_default_httponly",
            FindingCategory::FrameworkDefaultAssumed,
            Severity::Low,
            artifact,
            http_only.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` relies on HttpOnly framework default"),
            "The local code does not set HttpOnly directly; behavior appears to depend on a framework default."
                .to_string(),
            "Set HttpOnly explicitly or document the framework version and active default."
                .to_string(),
            "Which framework version and deployment settings determine HttpOnly here?".to_string(),
        )),
        _ => None,
    }
}

fn classify_same_site_posture(
    artifact: &Artifact,
    cookie_name: &str,
    same_site: &CookieAttributeObservation,
    secure: &CookieAttributeObservation,
    session_like: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if same_site_is_none(same_site) && secure.state == CookieAttributeState::Present {
        findings.push(finding(
            "cookie_samesite_none_cross_site_review",
            FindingCategory::DynamicReviewRequired,
            Severity::Low,
            artifact,
            combined_evidence_ids(same_site, secure),
            format!("Cookie `{cookie_name}` allows cross-site requests with SameSite=None"),
            "SameSite=None was detected with Secure evidence. This may be intentional for cross-site flows, but it broadens browser send behavior."
                .to_string(),
            "Confirm the cross-site requirement and use the narrowest SameSite value compatible with the flow."
                .to_string(),
            "Which cross-site flow requires this cookie to use SameSite=None?".to_string(),
        ));
    }

    if !session_like && artifact.artifact_type != ArtifactType::SignedCookie {
        return findings;
    }

    match same_site.state {
        CookieAttributeState::Missing if same_site.confidence == Confidence::High => {
            findings.push(finding(
                "cookie_missing_samesite",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::Medium,
                artifact,
                same_site.evidence_ids.clone(),
                format!("Session-like cookie `{cookie_name}` does not set SameSite"),
                "No SameSite attribute evidence was detected for this cookie-setting call."
                    .to_string(),
                "Set SameSite=Lax or SameSite=Strict unless a documented cross-site flow requires SameSite=None."
                    .to_string(),
                "Should this session-like cookie be sent on cross-site requests?".to_string(),
            ));
        }
        CookieAttributeState::Dynamic => findings.push(finding(
            "cookie_dynamic_samesite",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            same_site.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` has dynamic SameSite evidence"),
            "The SameSite attribute appears to depend on a non-literal expression.".to_string(),
            "Confirm the effective production SameSite value and set it explicitly when possible."
                .to_string(),
            "Can production guarantee an appropriate SameSite value for this cookie?".to_string(),
        )),
        CookieAttributeState::FrameworkDefault => findings.push(finding(
            "cookie_default_samesite",
            FindingCategory::FrameworkDefaultAssumed,
            Severity::Low,
            artifact,
            same_site.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` relies on SameSite framework default"),
            "The local code does not set SameSite directly; behavior appears to depend on a framework default."
                .to_string(),
            "Set SameSite explicitly or document the framework version and active default.".to_string(),
            "Which framework version and deployment settings determine SameSite here?".to_string(),
        )),
        _ => {}
    }

    findings
}

fn classify_lifetime_posture(
    artifact: &Artifact,
    cookie_name: &str,
    max_age: &CookieAttributeObservation,
    expires: &CookieAttributeObservation,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if max_age.state == CookieAttributeState::Present
        && max_age.confidence == Confidence::High
        && let Some(seconds) = max_age_seconds(artifact, max_age.value.as_deref())
        && seconds > EXCESSIVE_COOKIE_LIFETIME_SECONDS
    {
        findings.push(finding(
            "cookie_excessive_max_age",
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            max_age.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` has excessive Max-Age"),
            "Static Max-Age evidence exceeds the 30-day posture threshold for explicit cookie lifetime."
                .to_string(),
            "Use the shortest cookie lifetime compatible with the session or remember-me flow."
                .to_string(),
            "Why does this cookie need to remain valid for more than 30 days?".to_string(),
        ));
    }

    if expires.state == CookieAttributeState::Present && expires.confidence == Confidence::High {
        if let Some(seconds) = relative_expires_seconds(expires.value.as_deref()) {
            if seconds > EXCESSIVE_COOKIE_LIFETIME_SECONDS {
                findings.push(finding(
                    "cookie_excessive_expires",
                    FindingCategory::HighConfidenceMisconfiguration,
                    Severity::High,
                    artifact,
                    expires.evidence_ids.clone(),
                    format!("Cookie `{cookie_name}` has excessive Expires lifetime"),
                    "Static relative Expires evidence exceeds the 30-day posture threshold for explicit cookie lifetime."
                        .to_string(),
                    "Use the shortest cookie lifetime compatible with the session or remember-me flow."
                        .to_string(),
                    "Why does this cookie need to remain valid for more than 30 days?".to_string(),
                ));
            }
        } else if looks_like_far_future_expires(expires.value.as_deref()) {
            findings.push(finding(
                "cookie_absolute_expires_review",
                FindingCategory::DynamicReviewRequired,
                Severity::Low,
                artifact,
                expires.evidence_ids.clone(),
                format!("Cookie `{cookie_name}` uses an absolute far-future Expires value"),
                "An absolute Expires value appears long-lived, but static analysis cannot derive the effective duration from local source evidence."
                    .to_string(),
                "Confirm the effective lifetime and prefer a bounded Max-Age or locally derivable Expires duration."
                    .to_string(),
                "What effective lifetime does this absolute Expires value create in production?".to_string(),
            ));
        }
    }

    findings
}

fn classify_scope_posture(
    artifact: &Artifact,
    cookie_name: &str,
    path: &CookieAttributeObservation,
    domain: &CookieAttributeObservation,
    session_like: bool,
) -> Vec<Finding> {
    if !session_like && artifact.artifact_type != ArtifactType::SignedCookie {
        return Vec::new();
    }

    let mut findings = Vec::new();
    if domain.state == CookieAttributeState::Present
        && domain.confidence == Confidence::High
        && domain.value.as_deref().is_some_and(is_broad_cookie_domain)
    {
        findings.push(finding(
            "cookie_broad_domain_scope",
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            domain.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` uses broad Domain scope"),
            "Static Domain evidence broadens where the browser can send this session-like cookie."
                .to_string(),
            "Omit Domain for host-only cookies unless subdomain sharing is explicitly required."
                .to_string(),
            "Which hosts are intended to receive this cookie?".to_string(),
        ));
    } else if domain.state == CookieAttributeState::Dynamic {
        findings.push(finding(
            "cookie_dynamic_domain_scope",
            FindingCategory::DynamicReviewRequired,
            Severity::Low,
            artifact,
            domain.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` has dynamic Domain scope"),
            "The Domain attribute appears to depend on runtime configuration.".to_string(),
            "Confirm the effective production Domain value and document the intended host scope."
                .to_string(),
            "Which hosts can receive this cookie in production?".to_string(),
        ));
    }

    if path.state == CookieAttributeState::Present
        && path.confidence == Confidence::High
        && path
            .value
            .as_deref()
            .is_some_and(|value| value.trim() == "/")
    {
        findings.push(finding(
            "cookie_broad_path_scope",
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            path.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` uses broad Path scope"),
            "Static Path=/ evidence allows the browser to send this session-like cookie to every path on the host."
                .to_string(),
            "Use the narrowest Path compatible with the application flow.".to_string(),
            "Which application paths are intended to receive this cookie?".to_string(),
        ));
    } else if path.state == CookieAttributeState::Dynamic {
        findings.push(finding(
            "cookie_dynamic_path_scope",
            FindingCategory::DynamicReviewRequired,
            Severity::Low,
            artifact,
            path.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` has dynamic Path scope"),
            "The Path attribute appears to depend on runtime configuration.".to_string(),
            "Confirm the effective production Path value and document the intended route scope."
                .to_string(),
            "Which application paths can receive this cookie in production?".to_string(),
        ));
    }

    findings
}

fn classify_secure(
    artifact: &Artifact,
    cookie_name: &str,
    secure: &CookieAttributeObservation,
) -> Option<Finding> {
    match secure.state {
        CookieAttributeState::Missing if secure.confidence == Confidence::High => Some(finding(
            "cookie_missing_secure",
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            secure.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` does not set Secure"),
            "No Secure attribute evidence was detected for this cookie-setting call.".to_string(),
            "Set Secure for cookies that should only be sent over HTTPS.".to_string(),
            "Is this cookie ever used in an externally reachable production environment?"
                .to_string(),
        )),
        CookieAttributeState::FrameworkDefault
            if observation_value_is_false(secure) && secure.confidence == Confidence::Low =>
        {
            Some(finding(
                "cookie_default_false_secure",
                FindingCategory::FrameworkDefaultAssumed,
                Severity::Low,
                artifact,
                secure.evidence_ids.clone(),
                format!("Cookie `{cookie_name}` defaults Secure to false"),
                "Framework default evidence indicates Secure is false for this cookie-setting call."
                    .to_string(),
                "Set Secure explicitly or document the framework version and active default."
                    .to_string(),
                "Which framework version and deployment settings determine Secure here?".to_string(),
            ))
        }
        CookieAttributeState::Dynamic => Some(finding(
            "cookie_dynamic_secure",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            secure.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` has dynamic Secure evidence"),
            "The Secure attribute appears to depend on a non-literal expression.".to_string(),
            "Confirm the effective production value and set Secure explicitly when possible."
                .to_string(),
            "Can production guarantee Secure is enabled for this cookie?".to_string(),
        )),
        CookieAttributeState::FrameworkDefault => Some(finding(
            "cookie_default_secure",
            FindingCategory::FrameworkDefaultAssumed,
            Severity::Low,
            artifact,
            secure.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` relies on Secure framework default"),
            "The local code does not set Secure directly; behavior appears to depend on a framework default."
                .to_string(),
            "Set Secure explicitly or document the framework version and active default."
                .to_string(),
            "Which framework version and deployment settings determine Secure here?".to_string(),
        )),
        _ => None,
    }
}

fn classify_same_site_none_without_secure(
    artifact: &Artifact,
    cookie_name: &str,
    same_site: &CookieAttributeObservation,
    secure: &CookieAttributeObservation,
) -> Option<Finding> {
    if !same_site_is_none(same_site) {
        return None;
    }

    let evidence_ids = combined_evidence_ids(same_site, secure);
    match secure.state {
        CookieAttributeState::Missing => Some(finding(
            "cookie_samesite_none_without_secure",
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            evidence_ids,
            format!("Cookie `{cookie_name}` sets SameSite=None without Secure evidence"),
            "SameSite=None was detected, but Secure attribute evidence was not detected for this cookie-setting call."
                .to_string(),
            "Set Secure whenever SameSite=None is used.".to_string(),
            "Is this cookie intentionally available in cross-site requests?".to_string(),
        )),
        CookieAttributeState::Dynamic => Some(finding(
            "cookie_samesite_none_dynamic_secure",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            evidence_ids,
            format!("Cookie `{cookie_name}` sets SameSite=None with dynamic Secure evidence"),
            "SameSite=None was detected, while Secure appears to depend on a non-literal expression."
                .to_string(),
            "Confirm Secure is enabled whenever SameSite=None is active.".to_string(),
            "Can production guarantee Secure is enabled for this SameSite=None cookie?".to_string(),
        )),
        CookieAttributeState::FrameworkDefault => Some(finding(
            "cookie_samesite_none_default_secure",
            FindingCategory::FrameworkDefaultAssumed,
            Severity::Medium,
            artifact,
            evidence_ids,
            format!("Cookie `{cookie_name}` sets SameSite=None and relies on Secure default"),
            "SameSite=None was detected, while Secure appears to depend on a framework default."
                .to_string(),
            "Set Secure explicitly whenever SameSite=None is used.".to_string(),
            "Which framework version and deployment settings determine Secure here?".to_string(),
        )),
        _ => None,
    }
}

fn classify_expiry(
    artifact: &Artifact,
    cookie_name: &str,
    max_age: &CookieAttributeObservation,
    expires: &CookieAttributeObservation,
) -> Option<Finding> {
    if max_age.state == CookieAttributeState::Dynamic
        || expires.state == CookieAttributeState::Dynamic
    {
        return Some(finding(
            "cookie_dynamic_expiry",
            FindingCategory::DynamicReviewRequired,
            Severity::Low,
            artifact,
            combined_evidence_ids(max_age, expires),
            format!("Cookie `{cookie_name}` has dynamic expiry evidence"),
            "Cookie lifetime appears to depend on dynamic Max-Age or Expires evidence.".to_string(),
            "Confirm the effective cookie lifetime and document the production value.".to_string(),
            "What effective lifetime does this cookie have in production?".to_string(),
        ));
    }

    if is_expiry_absent(max_age) && is_expiry_absent(expires) {
        return Some(finding(
            "cookie_missing_expiry",
            FindingCategory::LifecycleGap,
            Severity::Low,
            artifact,
            combined_evidence_ids(max_age, expires),
            format!("Cookie `{cookie_name}` has no explicit expiry evidence"),
            "No Max-Age or Expires evidence was detected for this cookie-setting call."
                .to_string(),
            "Add an explicit Max-Age or Expires value when the cookie should have a bounded lifetime."
                .to_string(),
            "Should this cookie be session-scoped, or should it have an explicit lifetime?"
                .to_string(),
        ));
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule_id: &str,
    category: FindingCategory,
    severity: Severity,
    artifact: &Artifact,
    evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
) -> Finding {
    let artifact_id_part = artifact.id.0.as_str();
    let evidence_part = evidence_ids
        .first()
        .map(|evidence_id| evidence_id.0.as_str())
        .unwrap_or("no_evidence");
    let name_part = artifact.display_name.as_deref().unwrap_or("dynamic");
    let id = stable_finding_id(&[rule_id, artifact_id_part, evidence_part, name_part]);

    Finding {
        id,
        category,
        severity,
        artifact_ids: vec![artifact.id.clone()],
        evidence_ids,
        title,
        description,
        suggested_fix: Some(suggested_fix),
        reviewer_question: Some(reviewer_question),
    }
}

fn is_session_like_cookie(artifact: &Artifact) -> bool {
    if matches!(
        artifact.artifact_type,
        ArtifactType::SessionCookie | ArtifactType::SignedCookie
    ) {
        return true;
    }

    let Some(name) = &artifact.display_name else {
        return false;
    };
    let normalized = name.to_ascii_lowercase();
    matches!(normalized.as_str(), "session" | "sessionid" | "sid") || normalized.contains("session")
}

fn same_site_is_none(observation: &CookieAttributeObservation) -> bool {
    observation
        .value
        .as_deref()
        .map(|value| {
            value
                .trim_matches('"')
                .trim_matches('\'')
                .eq_ignore_ascii_case("none")
        })
        .unwrap_or(false)
}

fn observation_value_is_false(observation: &CookieAttributeObservation) -> bool {
    observation
        .value
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("false"))
}

fn is_expiry_absent(observation: &CookieAttributeObservation) -> bool {
    observation.state == CookieAttributeState::Missing
        || (observation.state == CookieAttributeState::FrameworkDefault
            && observation
                .value
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("none")))
}

fn max_age_seconds(artifact: &Artifact, value: Option<&str>) -> Option<i64> {
    let raw = value?;
    let amount = eval_numeric_expression(raw)?;
    if artifact
        .framework_hints
        .iter()
        .any(|hint| hint == "express")
    {
        Some(amount / 1000)
    } else {
        Some(amount)
    }
}

fn relative_expires_seconds(value: Option<&str>) -> Option<i64> {
    let raw = value?;
    let normalized = raw.to_ascii_lowercase();
    if normalized.contains("timedelta") {
        let days = named_number_argument(&normalized, "days").unwrap_or(0);
        let hours = named_number_argument(&normalized, "hours").unwrap_or(0);
        let minutes = named_number_argument(&normalized, "minutes").unwrap_or(0);
        let seconds = named_number_argument(&normalized, "seconds").unwrap_or(0);
        let total = days * 24 * 60 * 60 + hours * 60 * 60 + minutes * 60 + seconds;
        return (total > 0).then_some(total);
    }

    if let Some(index) = normalized.find("date.now") {
        let tail = &normalized[index..];
        let expression = tail
            .split_once('+')
            .map(|(_, expression)| expression)
            .unwrap_or_default();
        let milliseconds = eval_numeric_expression(expression)?;
        return Some(milliseconds / 1000);
    }

    None
}

fn looks_like_far_future_expires(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    ["2038", "2099", "9999"]
        .iter()
        .any(|year| value.contains(year))
}

fn named_number_argument(value: &str, name: &str) -> Option<i64> {
    let start = value.find(&format!("{name}="))? + name.len() + 1;
    let tail = &value[start..];
    let number = tail
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    number.parse().ok()
}

fn eval_numeric_expression(value: &str) -> Option<i64> {
    let mut parser = NumericExpressionParser::new(value);
    let parsed = parser.parse_expression()?;
    parser.finished().then_some(parsed)
}

struct NumericExpressionParser<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl<'a> NumericExpressionParser<'a> {
    fn new(value: &'a str) -> Self {
        Self {
            chars: value.chars().peekable(),
        }
    }

    fn parse_expression(&mut self) -> Option<i64> {
        let mut value = self.parse_term()?;
        loop {
            self.skip_ignored();
            if self.consume('+') {
                value = value.checked_add(self.parse_term()?)?;
            } else {
                return Some(value);
            }
        }
    }

    fn parse_term(&mut self) -> Option<i64> {
        let mut value = self.parse_factor()?;
        loop {
            self.skip_ignored();
            if self.consume('*') {
                value = value.checked_mul(self.parse_factor()?)?;
            } else if self.consume('/') {
                let divisor = self.parse_factor()?;
                if divisor == 0 {
                    return None;
                }
                value /= divisor;
            } else {
                return Some(value);
            }
        }
    }

    fn parse_factor(&mut self) -> Option<i64> {
        self.skip_ignored();
        if self.consume('(') {
            let value = self.parse_expression()?;
            self.skip_ignored();
            return self.consume(')').then_some(value);
        }
        self.parse_number()
    }

    fn parse_number(&mut self) -> Option<i64> {
        self.skip_ignored();
        let mut number = String::new();
        while let Some(ch) = self.chars.peek().copied() {
            if ch.is_ascii_digit() {
                number.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }
        (!number.is_empty())
            .then(|| number.parse::<i64>().ok())
            .flatten()
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.chars.peek().copied() == Some(expected) {
            self.chars.next();
            true
        } else {
            false
        }
    }

    fn skip_ignored(&mut self) {
        while self
            .chars
            .peek()
            .is_some_and(|ch| ch.is_whitespace() || *ch == '_')
        {
            self.chars.next();
        }
    }

    fn finished(&mut self) -> bool {
        self.skip_ignored();
        self.chars.peek().is_none()
    }
}

fn is_broad_cookie_domain(value: &str) -> bool {
    let domain = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty()
        || domain == "localhost"
        || domain.ends_with(".localhost")
        || domain.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    domain.contains('.')
}

fn combined_evidence_ids(
    left: &CookieAttributeObservation,
    right: &CookieAttributeObservation,
) -> Vec<EvidenceId> {
    let mut evidence_ids = left.evidence_ids.clone();
    evidence_ids.extend(right.evidence_ids.clone());
    evidence_ids.sort();
    evidence_ids.dedup();
    evidence_ids
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, CookieAttributes, LifecycleEvidence, SCHEMA_VERSION, ScanSummary,
        SourceLocation,
    };

    use super::*;

    fn classify_artifact(artifact: Artifact) -> Vec<Finding> {
        classify(&ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![artifact],
            evidence: Vec::new(),
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        })
    }

    fn artifact(name: &str, attributes: CookieAttributes) -> Artifact {
        Artifact {
            id: ArtifactId(format!("artifact_{name}")),
            artifact_type: ArtifactType::SessionCookie,
            display_name: Some(name.to_string()),
            locations: vec![SourceLocation {
                path: "app.ts".to_string(),
                line: Some(1),
                column: Some(1),
            }],
            lifecycle_evidence: LifecycleEvidence::default(),
            confidence: Confidence::High,
            framework_hints: vec!["express".to_string()],
            cookie_attributes: Some(attributes),
            jwt_attributes: None,
            token_boundary_attributes: None,
        }
    }

    fn attributes(
        http_only: CookieAttributeObservation,
        secure: CookieAttributeObservation,
        same_site: CookieAttributeObservation,
        max_age: CookieAttributeObservation,
        expires: CookieAttributeObservation,
    ) -> CookieAttributes {
        CookieAttributes {
            http_only,
            secure,
            same_site,
            max_age,
            expires,
            path: present("path", "/auth"),
            domain: missing("domain"),
        }
    }

    fn present(attribute: &str, value: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::Present,
            Some(value),
            Confidence::High,
        )
    }

    fn missing(attribute: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::Missing,
            None,
            Confidence::High,
        )
    }

    fn dynamic(attribute: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::Dynamic,
            Some("process.env.NODE_ENV === \"production\""),
            Confidence::Medium,
        )
    }

    fn default(attribute: &str, value: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::FrameworkDefault,
            Some(value),
            Confidence::Low,
        )
    }

    fn observation(
        attribute: &str,
        state: CookieAttributeState,
        value: Option<&str>,
        confidence: Confidence,
    ) -> CookieAttributeObservation {
        CookieAttributeObservation {
            state,
            value: value.map(str::to_string),
            evidence_ids: vec![EvidenceId(format!("evidence_{attribute}"))],
            confidence,
        }
    }

    fn attributes_with_scope(
        http_only: CookieAttributeObservation,
        secure: CookieAttributeObservation,
        same_site: CookieAttributeObservation,
        max_age: CookieAttributeObservation,
        expires: CookieAttributeObservation,
        path: CookieAttributeObservation,
        domain: CookieAttributeObservation,
    ) -> CookieAttributes {
        CookieAttributes {
            http_only,
            secure,
            same_site,
            max_age,
            expires,
            path,
            domain,
        }
    }

    #[test]
    fn missing_http_only_on_session_cookie_is_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                missing("http_only"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("HttpOnly")
        }));
    }

    #[test]
    fn missing_secure_on_static_cookie_is_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                missing("secure"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("Secure")
        }));
    }

    #[test]
    fn same_site_none_without_secure_links_both_evidence_ids() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                missing("secure"),
                present("same_site", "none"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("SameSite=None"))
            .expect("sameSite finding should exist");
        assert_eq!(
            finding.category,
            FindingCategory::HighConfidenceMisconfiguration
        );
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_secure".to_string()))
        );
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_same_site".to_string()))
        );
    }

    #[test]
    fn dynamic_secure_requires_review_not_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                dynamic("secure"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.title.contains("Secure")
        }));
        assert!(!findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("Secure")
        }));
    }

    #[test]
    fn framework_default_false_secure_is_framework_default_assumed() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                default("secure", "false"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::FrameworkDefaultAssumed
                && finding.severity == Severity::Low
                && finding.title.contains("Secure")
                && finding.title.contains("defaults")
        }));
    }

    #[test]
    fn framework_default_false_httponly_is_framework_default_assumed() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                default("http_only", "false"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::FrameworkDefaultAssumed
                && finding.severity == Severity::Low
                && finding.title.contains("HttpOnly")
                && finding.title.contains("defaults")
        }));
    }

    #[test]
    fn missing_expiry_is_lifecycle_gap_with_question() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                missing("max_age"),
                default("expires", "none"),
            ),
        ));

        let finding = findings
            .iter()
            .find(|finding| finding.category == FindingCategory::LifecycleGap)
            .expect("expiry lifecycle finding should exist");
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn excessive_max_age_uses_framework_units() {
        let mut exact_express = artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "2592000000"),
                missing("expires"),
            ),
        );
        exact_express.framework_hints = vec!["express".to_string()];
        assert!(
            !classify_artifact(exact_express)
                .iter()
                .any(|finding| finding.title.contains("Max-Age"))
        );

        let mut long_python = artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "2678401"),
                missing("expires"),
            ),
        );
        long_python.framework_hints = vec!["python".to_string()];
        assert!(classify_artifact(long_python).iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("Max-Age")
        }));
    }

    #[test]
    fn relative_and_far_future_expires_are_classified() {
        let relative = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                missing("max_age"),
                present("expires", "timedelta(days=45)"),
            ),
        ));
        assert!(relative.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("Expires")
        }));

        let absolute = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                missing("max_age"),
                present("expires", "Wed, 31 Dec 2099 23:59:59 GMT"),
            ),
        ));
        assert!(absolute.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.title.contains("absolute")
        }));
    }

    #[test]
    fn broad_domain_and_path_scope_are_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes_with_scope(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
                present("path", "/"),
                present("domain", ".example.com"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("Domain")
        }));
        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("Path")
        }));
    }

    #[test]
    fn samesite_posture_distinguishes_missing_none_dynamic_and_default() {
        let missing_findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                missing("same_site"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));
        assert!(missing_findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::Medium
                && finding.title.contains("SameSite")
        }));

        let none_findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "none"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));
        assert!(none_findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.title.contains("SameSite=None")
        }));

        let dynamic_findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                dynamic("same_site"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));
        assert!(dynamic_findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.title.contains("dynamic SameSite")
        }));

        let default_findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                default("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));
        assert!(default_findings.iter().any(|finding| {
            finding.category == FindingCategory::FrameworkDefaultAssumed
                && finding.title.contains("SameSite framework default")
        }));
    }

    #[test]
    fn safe_cookie_produces_no_findings() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn numeric_cookie_lifetime_parser_is_strict_and_parentheses_aware() {
        assert_eq!(
            eval_numeric_expression("(30 + 1) * 24 * 60 * 60"),
            Some(2_678_400)
        );
        assert_eq!(eval_numeric_expression("60 * (60 + 30) / 3"), Some(1_800));
        assert_eq!(eval_numeric_expression("Date.now() + 60 * 60"), None);
        assert_eq!(eval_numeric_expression("60 - 30"), None);
        assert_eq!(eval_numeric_expression("60 / 0"), None);
    }
}
