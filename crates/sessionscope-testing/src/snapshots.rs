pub fn normalize_snapshot_paths(input: &str) -> String {
    input.replace("\r\n", "\n").replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_windows_line_endings_and_paths() {
        assert_eq!(
            normalize_snapshot_paths("{\r\n  \"path\": \"dir\\file.ts\"\r\n}"),
            "{\n  \"path\": \"dir/file.ts\"\n}"
        );
    }
}
