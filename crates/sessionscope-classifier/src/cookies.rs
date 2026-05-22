use std::net::IpAddr;

use sessionscope_model::{
    Artifact, ArtifactType, Confidence, CookieAttributeObservation, CookieAttributeState, Evidence,
    EvidenceId, Finding, FindingCategory, ScanReport, Severity, stable_finding_id,
};

const EXCESSIVE_COOKIE_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(classify_conflicting_writes(report));

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

        let prefix_evidence =
            cookie_artifact_evidence(report, artifact, "cookie.attribute.name_prefix");
        let partitioned_evidence =
            cookie_artifact_evidence(report, artifact, "cookie.attribute.partitioned");
        findings.extend(classify_prefix_rules(
            artifact,
            cookie_name,
            prefix_evidence,
            &attributes.secure,
            &attributes.path,
            &attributes.domain,
        ));

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
        findings.extend(classify_partitioned_review(
            artifact,
            cookie_name,
            partitioned_evidence,
        ));
        findings.extend(classify_scope_posture(
            artifact,
            cookie_name,
            &attributes.path,
            &attributes.domain,
            session_like,
        ));
        findings.extend(classify_domain_leak_review(
            artifact,
            cookie_name,
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

fn classify_conflicting_writes(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    for evidence in report
        .evidence
        .iter()
        .filter(|evidence| evidence.detector_id == "cookie.conflicting_writes")
    {
        let artifacts = report
            .artifacts
            .iter()
            .filter(|artifact| artifact.lifecycle_evidence.store.contains(&evidence.id))
            .collect::<Vec<_>>();
        if artifacts.len() < 2 {
            continue;
        }
        let artifact = artifacts[0];
        let cookie_name = artifact.display_name.as_deref().unwrap_or("cookie");
        let mut artifact_ids = artifacts
            .iter()
            .map(|artifact| artifact.id.clone())
            .collect::<Vec<_>>();
        artifact_ids.sort();
        artifact_ids.dedup();
        let mut evidence_ids = vec![evidence.id.clone()];
        for artifact in &artifacts {
            evidence_ids.extend(
                artifact
                    .lifecycle_evidence
                    .store
                    .iter()
                    .filter(|evidence_id| {
                        report.evidence.iter().any(|candidate| {
                            candidate.id == **evidence_id && candidate.detector_id == "cookie.set"
                        })
                    })
                    .cloned(),
            );
        }
        evidence_ids.sort();
        evidence_ids.dedup();
        let mut finding = finding(
            "cookie_conflicting_writes_review",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            evidence_ids,
            format!("Cookie `{cookie_name}` is written multiple times in one handler"),
            "Multiple source-visible writes target the same cookie name in one handler scope. Static analysis cannot prove last-write-wins middleware behavior."
                .to_string(),
            "Consolidate cookie writes or document why repeated writes are intentional and ordered."
                .to_string(),
            "Which write controls the effective production cookie attributes?".to_string(),
        );
        finding.artifact_ids = artifact_ids;
        findings.push(finding);
    }
    findings
}

fn classify_prefix_rules(
    artifact: &Artifact,
    cookie_name: &str,
    prefix_evidence: Option<&Evidence>,
    secure: &CookieAttributeObservation,
    path: &CookieAttributeObservation,
    domain: &CookieAttributeObservation,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(prefix) = cookie_prefix(cookie_name) else {
        return findings;
    };

    if prefix == CookieNamePrefix::Host {
        if path.state == CookieAttributeState::Present
            && path.confidence == Confidence::High
            && path
                .value
                .as_deref()
                .is_none_or(|value| value.trim() != "/")
        {
            findings.push(finding(
                "cookie_host_prefix_path_violation",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                evidence_with_prefix(prefix_evidence, path),
                format!("Cookie `{cookie_name}` violates __Host- Path requirements"),
                "The __Host- prefix requires Path=/, but static Path evidence has a different value."
                    .to_string(),
                "Set Path=/ for __Host- cookies.".to_string(),
                "Should this __Host- cookie be scoped to the entire host with Path=/?".to_string(),
            ));
        } else if path.state == CookieAttributeState::Missing {
            findings.push(finding(
                "cookie_host_prefix_path_violation",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                evidence_with_prefix(prefix_evidence, path),
                format!("Cookie `{cookie_name}` violates __Host- Path requirements"),
                "The __Host- prefix requires explicit Path=/, but no Path evidence was detected."
                    .to_string(),
                "Set Path=/ for __Host- cookies.".to_string(),
                "Should this __Host- cookie be scoped to the entire host with Path=/?".to_string(),
            ));
        } else if path.state == CookieAttributeState::Dynamic {
            findings.push(finding(
                "cookie_host_prefix_path_violation",
                FindingCategory::DynamicReviewRequired,
                Severity::Medium,
                artifact,
                evidence_with_prefix(prefix_evidence, path),
                format!("Cookie `{cookie_name}` has dynamic __Host- Path evidence"),
                "The __Host- prefix requires Path=/, but the Path value depends on runtime configuration."
                    .to_string(),
                "Confirm production Path is / whenever the __Host- cookie is set.".to_string(),
                "Can production guarantee Path=/ for this __Host- cookie?".to_string(),
            ));
        }

        if domain.state == CookieAttributeState::Present {
            findings.push(finding(
                "cookie_host_prefix_domain_violation",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                evidence_with_prefix(prefix_evidence, domain),
                format!("Cookie `{cookie_name}` violates __Host- Domain requirements"),
                "The __Host- prefix forbids Domain, but static Domain evidence was detected."
                    .to_string(),
                "Omit Domain for __Host- cookies so they remain host-only.".to_string(),
                "Which host should own this __Host- cookie?".to_string(),
            ));
        } else if domain.state == CookieAttributeState::Dynamic {
            findings.push(finding(
                "cookie_host_prefix_domain_violation",
                FindingCategory::DynamicReviewRequired,
                Severity::Medium,
                artifact,
                evidence_with_prefix(prefix_evidence, domain),
                format!("Cookie `{cookie_name}` has dynamic __Host- Domain evidence"),
                "The __Host- prefix forbids Domain, but Domain depends on runtime configuration."
                    .to_string(),
                "Confirm production never sets Domain for this __Host- cookie.".to_string(),
                "Can production guarantee Domain is omitted for this __Host- cookie?".to_string(),
            ));
        }
    }

    if matches!(prefix, CookieNamePrefix::Host | CookieNamePrefix::Secure) {
        if secure.state == CookieAttributeState::Missing {
            let rule_id = if prefix == CookieNamePrefix::Host {
                "cookie_host_prefix_secure_violation"
            } else {
                "cookie_secure_prefix_secure_violation"
            };
            let prefix_label = prefix.label();
            findings.push(finding(
                rule_id,
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                evidence_with_prefix(prefix_evidence, secure),
                format!("Cookie `{cookie_name}` violates {prefix_label} Secure requirements"),
                format!("The {prefix_label} prefix requires Secure, but no Secure evidence was detected."),
                format!("Set Secure for {prefix_label} cookies."),
                format!("Can this {prefix_label} cookie ever be set without HTTPS-only transport?"),
            ));
        } else if matches!(
            secure.state,
            CookieAttributeState::Dynamic | CookieAttributeState::FrameworkDefault
        ) {
            let rule_id = if prefix == CookieNamePrefix::Host {
                "cookie_host_prefix_secure_violation"
            } else {
                "cookie_secure_prefix_secure_violation"
            };
            let prefix_label = prefix.label();
            findings.push(finding(
                rule_id,
                FindingCategory::DynamicReviewRequired,
                Severity::Medium,
                artifact,
                evidence_with_prefix(prefix_evidence, secure),
                format!("Cookie `{cookie_name}` has uncertain {prefix_label} Secure evidence"),
                format!("The {prefix_label} prefix requires Secure, but Secure depends on runtime or framework-default behavior."),
                format!("Set Secure explicitly for {prefix_label} cookies."),
                format!("Can production guarantee Secure is enabled for this {prefix_label} cookie?"),
            ));
        }
    }

    findings
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookieNamePrefix {
    Host,
    Secure,
}

impl CookieNamePrefix {
    fn label(self) -> &'static str {
        match self {
            Self::Host => "__Host-",
            Self::Secure => "__Secure-",
        }
    }
}

fn cookie_prefix(cookie_name: &str) -> Option<CookieNamePrefix> {
    if cookie_name.starts_with("__Host-") {
        Some(CookieNamePrefix::Host)
    } else if cookie_name.starts_with("__Secure-") {
        Some(CookieNamePrefix::Secure)
    } else {
        None
    }
}

fn cookie_artifact_evidence<'a>(
    report: &'a ScanReport,
    artifact: &Artifact,
    detector_id: &str,
) -> Option<&'a Evidence> {
    report.evidence.iter().find(|evidence| {
        evidence.detector_id == detector_id
            && (artifact.lifecycle_evidence.store.contains(&evidence.id)
                || artifact.lifecycle_evidence.transmit.contains(&evidence.id))
    })
}

fn evidence_with_prefix(
    prefix_evidence: Option<&Evidence>,
    observation: &CookieAttributeObservation,
) -> Vec<EvidenceId> {
    let mut evidence_ids = observation.evidence_ids.clone();
    if let Some(prefix_evidence) = prefix_evidence {
        evidence_ids.push(prefix_evidence.id.clone());
    }
    evidence_ids.sort();
    evidence_ids.dedup();
    evidence_ids
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

fn classify_partitioned_review(
    artifact: &Artifact,
    cookie_name: &str,
    partitioned_evidence: Option<&Evidence>,
) -> Option<Finding> {
    let evidence = partitioned_evidence?;
    Some(finding(
        "cookie_partitioned_review",
        FindingCategory::DynamicReviewRequired,
        Severity::Low,
        artifact,
        vec![evidence.id.clone()],
        format!("Cookie `{cookie_name}` uses the Partitioned attribute"),
        "Partitioned cookie evidence was detected. Static source cannot determine whether the CHIPS/embed context is intentional."
            .to_string(),
        "Confirm the partitioned-cookie requirement and document the embedded context that needs it."
            .to_string(),
        "Which embedded or third-party context requires this cookie to be Partitioned?".to_string(),
    ))
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
        && cookie_prefix(cookie_name) != Some(CookieNamePrefix::Host)
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

fn classify_domain_leak_review(
    artifact: &Artifact,
    cookie_name: &str,
    domain: &CookieAttributeObservation,
    session_like: bool,
) -> Vec<Finding> {
    if session_like || artifact.artifact_type == ArtifactType::SignedCookie {
        return Vec::new();
    }

    if domain.state == CookieAttributeState::Present
        && domain.confidence == Confidence::High
        && domain.value.as_deref().is_some_and(is_broad_cookie_domain)
    {
        vec![finding(
            "cookie_domain_leak_review",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            domain.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` sets a broad Domain attribute"),
            "Static Domain evidence broadens where the browser can send this cookie, but SessionScope cannot prove the intended host boundary."
                .to_string(),
            "Confirm the cookie is intended to be shared across the configured domain; otherwise omit Domain."
                .to_string(),
            "Which hosts are intended to receive this cookie?".to_string(),
        )]
    } else {
        Vec::new()
    }
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
        ArtifactId, CookieAttributes, Evidence, LifecycleEvidence, LifecycleStage, SCHEMA_VERSION,
        SanitizedExcerpt, ScanSummary, SourceLocation,
    };

    use super::*;

    fn classify_artifact(artifact: Artifact) -> Vec<Finding> {
        classify_report(vec![artifact], Vec::new())
    }

    fn classify_report(artifacts: Vec<Artifact>, evidence: Vec<Evidence>) -> Vec<Finding> {
        classify(&ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts,
            evidence,
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

    fn with_prefix_evidence(mut artifact: Artifact, prefix: &str) -> (Artifact, Evidence) {
        let evidence_id = EvidenceId(format!("evidence_prefix_{prefix}"));
        artifact.lifecycle_evidence.store.push(evidence_id.clone());
        (
            artifact,
            evidence(
                evidence_id,
                "cookie.attribute.name_prefix",
                LifecycleStage::Store,
                format!("Cookie name prefix: {prefix}"),
            ),
        )
    }

    fn with_partitioned_evidence(mut artifact: Artifact) -> (Artifact, Evidence) {
        let evidence_id = EvidenceId("evidence_partitioned".to_string());
        artifact
            .lifecycle_evidence
            .transmit
            .push(evidence_id.clone());
        (
            artifact,
            evidence(
                evidence_id,
                "cookie.attribute.partitioned",
                LifecycleStage::Transmit,
                "Partitioned: true".to_string(),
            ),
        )
    }

    fn with_conflict_evidence(mut artifacts: Vec<Artifact>) -> (Vec<Artifact>, Vec<Evidence>) {
        let conflict_id = EvidenceId("evidence_conflict".to_string());
        let mut evidence_items = vec![evidence(
            conflict_id.clone(),
            "cookie.conflicting_writes",
            LifecycleStage::Store,
            "Conflicting cookie writes for `session` in one handler".to_string(),
        )];
        for (index, artifact) in artifacts.iter_mut().enumerate() {
            let set_id = EvidenceId(format!("evidence_cookie_set_{index}"));
            artifact.lifecycle_evidence.store.push(set_id.clone());
            artifact.lifecycle_evidence.store.push(conflict_id.clone());
            evidence_items.push(evidence(
                set_id,
                "cookie.set",
                LifecycleStage::Store,
                format!("cookie write {index}"),
            ));
        }
        (artifacts, evidence_items)
    }

    fn evidence(
        evidence_id: EvidenceId,
        detector_id: &str,
        stage: LifecycleStage,
        excerpt: String,
    ) -> Evidence {
        Evidence {
            id: evidence_id,
            lifecycle_stage: stage,
            location: SourceLocation {
                path: "app.ts".to_string(),
                line: Some(1),
                column: Some(1),
            },
            detector_id: detector_id.to_string(),
            confidence: Confidence::High,
            excerpt: Some(SanitizedExcerpt::from_sanitized(excerpt)),
            dynamic: false,
            framework_default: false,
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
    fn host_prefix_literal_violations_are_high_confidence_and_evidence_bound() {
        let (artifact, prefix_evidence) = with_prefix_evidence(
            artifact(
                "__Host-session",
                attributes_with_scope(
                    present("http_only", "true"),
                    missing("secure"),
                    present("same_site", "lax"),
                    present("max_age", "900"),
                    missing("expires"),
                    present("path", "/auth"),
                    present("domain", "example.com"),
                ),
            ),
            "host",
        );
        let prefix_id = prefix_evidence.id.clone();
        let findings = classify_report(vec![artifact], vec![prefix_evidence]);

        for title_part in [
            "Path requirements",
            "Domain requirements",
            "Secure requirements",
        ] {
            let finding = findings
                .iter()
                .find(|finding| finding.title.contains(title_part))
                .unwrap_or_else(|| panic!("expected finding containing {title_part}"));
            assert_eq!(
                finding.category,
                FindingCategory::HighConfidenceMisconfiguration
            );
            assert_eq!(finding.severity, Severity::High);
            assert!(finding.evidence_ids.contains(&prefix_id));
        }
    }

    #[test]
    fn secure_prefix_missing_secure_is_high_confidence() {
        let (artifact, prefix_evidence) = with_prefix_evidence(
            artifact(
                "__Secure-session",
                attributes(
                    present("http_only", "true"),
                    missing("secure"),
                    present("same_site", "lax"),
                    present("max_age", "900"),
                    missing("expires"),
                ),
            ),
            "secure",
        );
        let prefix_id = prefix_evidence.id.clone();
        let findings = classify_report(vec![artifact], vec![prefix_evidence]);

        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("__Secure- Secure requirements"))
            .expect("secure-prefix finding should exist");
        assert_eq!(
            finding.category,
            FindingCategory::HighConfidenceMisconfiguration
        );
        assert!(finding.evidence_ids.contains(&prefix_id));
    }

    #[test]
    fn dynamic_host_prefix_path_requires_review() {
        let (artifact, prefix_evidence) = with_prefix_evidence(
            artifact(
                "__Host-session",
                attributes_with_scope(
                    present("http_only", "true"),
                    present("secure", "true"),
                    present("same_site", "lax"),
                    present("max_age", "900"),
                    missing("expires"),
                    dynamic("path"),
                    missing("domain"),
                ),
            ),
            "host",
        );
        let findings = classify_report(vec![artifact], vec![prefix_evidence]);

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.severity == Severity::Medium
                && finding.title.contains("dynamic __Host- Path")
        }));
    }

    #[test]
    fn compliant_prefixed_cookies_do_not_emit_prefix_findings() {
        let host = with_prefix_evidence(
            artifact(
                "__Host-session",
                attributes_with_scope(
                    present("http_only", "true"),
                    present("secure", "true"),
                    present("same_site", "lax"),
                    present("max_age", "900"),
                    missing("expires"),
                    present("path", "/"),
                    missing("domain"),
                ),
            ),
            "host",
        );
        let secure = with_prefix_evidence(
            artifact(
                "__Secure-session",
                attributes(
                    present("http_only", "true"),
                    present("secure", "true"),
                    present("same_site", "lax"),
                    present("max_age", "900"),
                    missing("expires"),
                ),
            ),
            "secure",
        );
        let findings = classify_report(vec![host.0, secure.0], vec![host.1, secure.1]);

        assert!(!findings.iter().any(|finding| {
            finding.title.contains("requirements")
                || finding.title.contains("uncertain __Host-")
                || finding.title.contains("uncertain __Secure-")
                || finding.title.contains("broad Path scope")
        }));
    }

    #[test]
    fn conflicting_cookie_writes_require_review() {
        let first = artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        );
        let mut second = artifact(
            "session",
            attributes(
                present("http_only", "true"),
                missing("secure"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        );
        second.id = ArtifactId("artifact_session_second".to_string());
        let (artifacts, evidence_items) = with_conflict_evidence(vec![first, second]);
        let evidence_ids = evidence_items
            .iter()
            .map(|evidence| evidence.id.clone())
            .collect::<Vec<_>>();
        let findings = classify_report(artifacts, evidence_items);

        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("written multiple times"))
            .expect("conflict finding should exist");
        assert_eq!(finding.category, FindingCategory::DynamicReviewRequired);
        assert_eq!(finding.severity, Severity::Medium);
        for evidence_id in evidence_ids {
            assert!(finding.evidence_ids.contains(&evidence_id));
        }
        assert_eq!(finding.artifact_ids.len(), 2);
    }

    #[test]
    fn partitioned_cookie_requires_review() {
        let (artifact, partitioned_evidence) = with_partitioned_evidence(artifact(
            "chips",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "none"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));
        let evidence_id = partitioned_evidence.id.clone();
        let findings = classify_report(vec![artifact], vec![partitioned_evidence]);

        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("Partitioned"))
            .expect("Partitioned finding should exist");
        assert_eq!(finding.category, FindingCategory::DynamicReviewRequired);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.evidence_ids, vec![evidence_id]);
    }

    #[test]
    fn broad_domain_non_session_cookie_is_domain_leak_review() {
        let mut artifact = artifact(
            "prefs",
            attributes_with_scope(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
                present("path", "/auth"),
                present("domain", ".example.com"),
            ),
        );
        artifact.artifact_type = ArtifactType::Unknown;
        let findings = classify_artifact(artifact);

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.severity == Severity::Medium
                && finding.title.contains("broad Domain")
        }));
        assert!(!findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("broad Domain scope")
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
