use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub root: PathBuf,
    pub max_file_size_bytes: u64,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub exclude_dirs: Vec<String>,
    pub sensitive_patterns: Vec<String>,
    pub custom_include_patterns: bool,
}

impl ScanConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_file_size_bytes: 1_000_000,
            include_patterns: default_include_patterns(),
            exclude_patterns: default_exclude_patterns(),
            exclude_dirs: vec![
                ".git".into(),
                "node_modules".into(),
                ".venv".into(),
                "venv".into(),
                "dist".into(),
                "build".into(),
                "target".into(),
                "coverage".into(),
                ".next".into(),
                "__pycache__".into(),
            ],
            sensitive_patterns: sensitive_patterns(),
            custom_include_patterns: false,
        }
    }

    pub fn set_include_patterns(&mut self, patterns: Vec<String>) {
        self.include_patterns = patterns;
        self.custom_include_patterns = true;
    }

    pub fn add_exclude_patterns(&mut self, patterns: Vec<String>) {
        self.exclude_patterns.extend(patterns);
    }

    pub fn set_max_file_size_bytes(&mut self, max_file_size_bytes: u64) {
        self.max_file_size_bytes = max_file_size_bytes;
    }
}

fn default_include_patterns() -> Vec<String> {
    [
        "**/*.js",
        "**/*.jsx",
        "**/*.ts",
        "**/*.tsx",
        "**/*.py",
        "**/*.json",
        "**/*.yaml",
        "**/*.yml",
        "**/*.toml",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_exclude_patterns() -> Vec<String> {
    [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn sensitive_patterns() -> Vec<String> {
    [
        ".env",
        ".env.*",
        "**/.env",
        "**/.env.*",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "id_rsa",
        "id_dsa",
        "**/id_rsa",
        "**/id_dsa",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
