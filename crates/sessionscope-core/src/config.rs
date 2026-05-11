use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub root: PathBuf,
    pub max_file_size_bytes: u64,
    pub include_extensions: Vec<String>,
    pub exclude_dirs: Vec<String>,
}

impl ScanConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_file_size_bytes: 1_000_000,
            include_extensions: vec![
                "js".into(),
                "jsx".into(),
                "ts".into(),
                "tsx".into(),
                "py".into(),
                "json".into(),
                "yaml".into(),
                "yml".into(),
                "toml".into(),
            ],
            exclude_dirs: vec![
                ".git".into(),
                "node_modules".into(),
                ".venv".into(),
                "dist".into(),
                "build".into(),
                "target".into(),
                "coverage".into(),
            ],
        }
    }
}
