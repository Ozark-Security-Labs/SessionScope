const REDACTION: &str = "[REDACTED]";

pub fn safe_excerpt(source: &str, max_chars: usize) -> String {
    let excerpt: String = source.chars().take(max_chars).collect();
    redact_sensitive_values(&excerpt)
}

pub fn redact_sensitive_values(input: &str) -> String {
    input
        .split_whitespace()
        .map(|part| {
            if looks_sensitive(part) {
                REDACTION
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_sensitive(value: &str) -> bool {
    let trimmed =
        value.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_');
    let dot_count = trimmed.matches('.').count();
    let long_alnum = trimmed.len() >= 32
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');

    dot_count == 2 && trimmed.len() > 24 || long_alnum
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_values;

    #[test]
    fn redacts_jwt_like_values() {
        let output =
            redact_sensitive_values("Authorization: Bearer aaa.bbb.cccccccccccccccccccccc");

        assert!(output.contains("[REDACTED]"));
    }
}
