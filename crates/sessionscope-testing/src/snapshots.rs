pub fn normalize_snapshot_paths(input: &str) -> String {
    input.replace('\\', "/")
}
