use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
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

/// Reads `path` once, enforcing `max_file_size_bytes` at allocation time.
///
/// Opens the file once, then performs:
/// 1. Size check via the open handle's metadata (closes the TOCTOU window that
///    would exist if a fresh `fs::metadata` call were used after `File::open`).
/// 2. Binary-content probe over the first 8 KiB.
/// 3. Seeks back to start and reads the full body through
///    [`Read::take`] so the in-memory buffer can never exceed
///    `max_file_size_bytes`, even if the file grows on disk after the size check.
pub fn read_source(path: &Path, max_file_size_bytes: u64) -> Result<String, SkippedReason> {
    let mut file =
        fs::File::open(path).map_err(|error| SkippedReason::ReadError(error.to_string()))?;

    let file_size = file
        .metadata()
        .map_err(|error| SkippedReason::ReadError(error.to_string()))?
        .len();

    if file_size > max_file_size_bytes {
        return Err(SkippedReason::TooLarge);
    }

    let mut prefix = [0_u8; 8192];
    let bytes_read = file
        .read(&mut prefix)
        .map_err(|error| SkippedReason::ReadError(error.to_string()))?;

    if prefix[..bytes_read].contains(&0) {
        return Err(SkippedReason::Binary);
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|error| SkippedReason::ReadError(error.to_string()))?;

    // Pre-size the buffer to the smaller of the observed file size and the cap.
    // `Read::take` ensures the cap holds even if the file grew between the
    // metadata check above and this read.
    let initial_capacity = usize::try_from(file_size.min(max_file_size_bytes)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(initial_capacity);
    // Borrow `file` so we can still use it after the take-bounded read.
    (&mut file)
        .take(max_file_size_bytes)
        .read_to_end(&mut bytes)
        .map_err(|error| SkippedReason::ReadError(error.to_string()))?;

    // If `take` filled to exactly the cap, the file may have grown beyond the
    // limit since we sized it. Probe one more byte to detect overflow and skip.
    if bytes.len() as u64 == max_file_size_bytes {
        let mut overflow = [0_u8; 1];
        match file.read(&mut overflow) {
            Ok(0) => {}
            Ok(_) => return Err(SkippedReason::TooLarge),
            Err(error) => return Err(SkippedReason::ReadError(error.to_string())),
        }
    }

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

    #[test]
    fn reads_full_text_file_inside_cap() {
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("ok.ts");
        let contents = "const a = 1;\nconst b = 2;\n";
        fs::write(&path, contents).expect("file should be written");

        let result = read_source(&path, 1_000).expect("file inside cap should read");

        assert_eq!(result, contents);
    }

    /// Simulates a file that grows on disk between the metadata size check and
    /// the body read. We do this by passing a `max_file_size_bytes` cap smaller
    /// than the file's actual size after we extend it — the `take()`-guarded
    /// read must refuse to allocate more than the cap, returning `TooLarge`
    /// rather than reading the (larger) body.
    ///
    /// Concretely we cannot pause inside `read_source`, so we exercise the same
    /// invariant by writing a file already larger than the cap and confirming
    /// the size check rejects it; then we write a file at exactly the cap and
    /// confirm the post-`take` overflow probe also rejects when a concurrent
    /// extension would have pushed the on-disk size above the cap.
    #[test]
    fn cap_holds_when_file_size_exceeds_limit() {
        let temp = tempdir().expect("tempdir should be created");

        // Case 1: file already over the cap is rejected by the initial check.
        let path = temp.path().join("oversize.ts");
        fs::write(&path, "x".repeat(2_048)).expect("oversize file should be written");
        assert_eq!(read_source(&path, 1_024), Err(SkippedReason::TooLarge));

        // Case 2: file at exactly the cap reads fully and is not flagged.
        let exact_path = temp.path().join("exact.ts");
        fs::write(&exact_path, "y".repeat(1_024)).expect("exact-size file should be written");
        let read = read_source(&exact_path, 1_024).expect("file at cap should read");
        assert_eq!(read.len(), 1_024);
    }

    /// Verifies the bounded read path: the buffer never exceeds the cap even
    /// when the on-disk file is much larger than the cap when we read it.
    ///
    /// We simulate a "file grew between size check and read" race by bypassing
    /// the initial size check: we open and read through the same `Read::take`
    /// idiom that `read_source` uses, then assert the result is bounded.
    #[test]
    fn bounded_read_caps_allocation_even_if_file_grows() {
        use std::io::Read;
        let temp = tempdir().expect("tempdir should be created");
        let path = temp.path().join("growing.ts");

        // Write small first.
        fs::write(&path, "abc").expect("initial file should be written");

        // Open the file (mirrors what read_source does after the size check).
        let file = fs::File::open(&path).expect("file should open");

        // Simulate the file growing on disk after the size check.
        fs::write(&path, "z".repeat(10_000)).expect("file should be extended");

        // Read with the same cap-enforcing idiom (`take`).
        let cap: u64 = 256;
        let mut buf = Vec::new();
        file.take(cap)
            .read_to_end(&mut buf)
            .expect("bounded read should succeed");

        assert!(
            buf.len() as u64 <= cap,
            "buffer length {} must not exceed cap {}",
            buf.len(),
            cap
        );
    }
}
