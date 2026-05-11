use std::fs;
use std::io;
use std::path::Path;

use sessionscope_model::{Language, SkippedReason};

pub fn classify_language(path: &Path) -> Language {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("js" | "jsx") => Language::JavaScript,
        Some("ts" | "tsx") => Language::TypeScript,
        Some("py") => Language::Python,
        Some("json") => Language::Json,
        Some("yaml" | "yml") => Language::Yaml,
        Some("toml") => Language::Toml,
        Some("txt" | "md") => Language::Text,
        _ => Language::Unknown,
    }
}

pub fn read_source(path: &Path, max_file_size_bytes: u64) -> Result<String, SkippedReason> {
    let metadata =
        fs::metadata(path).map_err(|error| SkippedReason::ReadError(error.to_string()))?;

    if metadata.len() > max_file_size_bytes {
        return Err(SkippedReason::TooLarge);
    }

    let bytes = fs::read(path).map_err(|error| SkippedReason::ReadError(error.to_string()))?;

    if bytes.contains(&0) {
        return Err(SkippedReason::Binary);
    }

    String::from_utf8(bytes).map_err(|error| {
        SkippedReason::ReadError(io::Error::new(io::ErrorKind::InvalidData, error).to_string())
    })
}
