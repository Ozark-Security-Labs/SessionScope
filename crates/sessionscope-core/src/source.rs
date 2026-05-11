use std::fs;
use std::io::{self, Read};
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

    let mut file =
        fs::File::open(path).map_err(|error| SkippedReason::ReadError(error.to_string()))?;
    let mut prefix = [0; 8192];
    let bytes_read = file
        .read(&mut prefix)
        .map_err(|error| SkippedReason::ReadError(error.to_string()))?;

    if prefix[..bytes_read].contains(&0) {
        return Err(SkippedReason::Binary);
    }

    let bytes = fs::read(path).map_err(|error| SkippedReason::ReadError(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| {
        SkippedReason::ReadError(io::Error::new(io::ErrorKind::InvalidData, error).to_string())
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sessionscope_model::SkippedReason;
    use tempfile::tempdir;

    use super::read_source;

    #[test]
    fn skips_large_files_before_reading_source_text() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("large.ts");
        fs::write(&path, "const token = 'not-read';").expect("large file should be written");

        let result = read_source(&path, 4);

        assert_eq!(result, Err(SkippedReason::TooLarge));
    }

    #[test]
    fn skips_binary_files_from_prefix() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("binary.ts");
        fs::write(&path, [0_u8, 159, 146, 150]).expect("binary file should be written");

        let result = read_source(&path, 1_000);

        assert_eq!(result, Err(SkippedReason::Binary));
    }
}
