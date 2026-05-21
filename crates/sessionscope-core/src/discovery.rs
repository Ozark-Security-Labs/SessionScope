use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use sessionscope_model::{FileScanResult, SkippedReason};

use crate::ScanConfig;
use crate::source::classify_language;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub files: Vec<PathBuf>,
    pub skipped: Vec<FileScanResult>,
}

pub fn discover_files(config: &ScanConfig) -> io::Result<DiscoveryResult> {
    let include_globs = compile_globs(&config.include_patterns)?;
    let exclude_globs = compile_globs(&config.exclude_patterns)?;
    let sensitive_globs = compile_globs(&config.sensitive_patterns)?;
    let mut files = Vec::new();
    let mut skipped = Vec::new();

    let mut builder = WalkBuilder::new(&config.root);
    builder
        .hidden(false)
        .ignore(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        // Disable parent traversal so the walker never reads `.gitignore`,
        // `.ignore`, or `.git/info/exclude` files located above the scan
        // root. SessionScope is run against arbitrary directories (including
        // those nested inside unrelated repositories), and reading parent
        // ignore files would let configuration outside the scan root affect
        // discovery behaviour or, worse, leak file contents from above the
        // root through error messages (F-16).
        .parents(false);
    let root = config.root.clone();
    let exclude_dirs = config.exclude_dirs.clone();
    builder.filter_entry(move |entry| {
        let path = entry.path();
        if path == root {
            return true;
        }

        // If a directory entry cannot be expressed as a path beneath the
        // configured scan root, refuse to descend rather than scanning an
        // arbitrary external location (F-17).
        match relative_path(&root, path) {
            Ok(relative) => !is_in_excluded_dir(&relative, &exclude_dirs),
            Err(_) => false,
        }
    });

    for entry in builder.build() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let path = entry.path();

        // F-03: refuse symlinks. The walker is not configured to follow
        // links, but an in-tree link still surfaces as an entry; reading
        // it would let a hostile target point an in-tree filename at an
        // arbitrary file on the runner. Skip the link itself, never
        // chase it.
        let symlink_metadata = fs::symlink_metadata(path).ok();
        let is_symlink = entry.path_is_symlink()
            || symlink_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.file_type().is_symlink());
        if is_symlink {
            let display = relative_path(&config.root, path)
                .map(|rel| normalize_path(&rel))
                .unwrap_or_else(|_| {
                    // Symlink outside the scan root: don't leak its absolute
                    // target path. Use only the file basename for display.
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "<symlink>".to_string())
                });
            let language = classify_language(path);
            skipped.push(FileScanResult::skipped(
                display,
                language,
                SkippedReason::Symlink,
            ));
            continue;
        }

        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let language = classify_language(path);

        // F-03 defense-in-depth: verify the file resolves inside the
        // canonical scan root before treating it as discovered. If
        // canonicalization fails or escapes the root, refuse the file
        // with `Symlink` (the most common reason for an outside-root
        // resolution on a real-world target).
        if !path_is_inside_canonical_root(path, &config.canonical_root) {
            // Use the file basename for display so we don't leak the
            // absolute path the symlink resolved to (F-17).
            let display = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<outside-root>".to_string());
            skipped.push(FileScanResult::skipped(
                display,
                language,
                SkippedReason::Symlink,
            ));
            continue;
        }

        // F-17: any path that does not strip cleanly against the scan root is
        // treated as a hard skip with the reason returned by `relative_path`
        // (typically `Excluded`). Falling back to the absolute path would let
        // symlinks and other escape routes place files outside the scan root
        // into the report under their absolute filesystem locations.
        let relative_path = match relative_path(&config.root, path) {
            Ok(relative) => relative,
            Err(reason) => {
                let display = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "<outside-root>".to_string());
                skipped.push(FileScanResult::skipped(display, language, reason));
                continue;
            }
        };

        let skipped_reason = if sensitive_globs.is_match(&relative_path) {
            Some(SkippedReason::SensitivePath)
        } else if is_in_excluded_dir(&relative_path, &config.exclude_dirs)
            || exclude_globs.is_match(&relative_path)
        {
            Some(SkippedReason::Excluded)
        } else if !include_globs.is_match(&relative_path) {
            if config.custom_include_patterns {
                Some(SkippedReason::Excluded)
            } else {
                Some(SkippedReason::Unsupported)
            }
        } else {
            None
        };

        if let Some(reason) = skipped_reason {
            skipped.push(FileScanResult::skipped(
                normalize_path(&relative_path),
                language,
                reason,
            ));
        } else {
            files.push(path.to_path_buf());
        }
    }

    files.sort_by_key(|path| {
        relative_path(&config.root, path)
            .map(|relative| normalize_path(&relative))
            .unwrap_or_else(|_| normalize_path(path))
    });
    skipped.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(DiscoveryResult { files, skipped })
}

fn compile_globs(patterns: &[String]) -> io::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();

    for pattern in patterns {
        add_glob_pattern(&mut builder, pattern)?;
    }

    builder
        .build()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
}

fn add_glob_pattern(builder: &mut GlobSetBuilder, pattern: &str) -> io::Result<()> {
    let normalized = pattern.trim().replace('\\', "/");
    if normalized.is_empty() {
        return Ok(());
    }

    add_one_glob(builder, &normalized)?;

    if !normalized.contains('/') && !normalized.starts_with("**/") {
        add_one_glob(builder, &format!("**/{normalized}"))?;
    }

    Ok(())
}

fn add_one_glob(builder: &mut GlobSetBuilder, pattern: &str) -> io::Result<()> {
    builder.add(
        Glob::new(pattern)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?,
    );
    Ok(())
}

fn is_in_excluded_dir(path: &Path, exclude_dirs: &[String]) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| exclude_dirs.iter().any(|excluded| excluded == name))
    })
}

/// Convert an absolute filesystem path into one expressed relative to the scan
/// root. A failed strip is treated as a hard skip with reason `Excluded`
/// (F-17): without it a symlink or `..` escape could otherwise inject an
/// absolute path from outside the scan root into the report.
fn relative_path(root: &Path, path: &Path) -> Result<PathBuf, SkippedReason> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| SkippedReason::Excluded)
}

/// Returns true when the file's canonicalized path is contained within
/// the canonical scan root. F-03 defense-in-depth: even if a link slips
/// past the `path_is_symlink` check, a target outside the root will
/// fail this containment test.
fn path_is_inside_canonical_root(path: &Path, canonical_root: &Path) -> bool {
    let canonical_path = match fs::canonicalize(path) {
        Ok(canonical_path) => canonical_path,
        Err(_) => return false,
    };
    canonical_path.starts_with(canonical_root)
}

pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sessionscope_model::SkippedReason;
    use tempfile::tempdir;

    use super::{discover_files, normalize_path};
    use crate::ScanConfig;

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_during_discovery() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir should be created");
        // Plant a normal source file plus a symlink to /etc/passwd
        // inside the tree. F-03: the link must be reported as
        // Skipped(Symlink) and its target must NOT appear anywhere in
        // the discovered file list.
        fs::write(temp.path().join("real.ts"), "const ok = true;")
            .expect("source file should be written");
        let link = temp.path().join("escape.ts");
        symlink("/etc/passwd", &link).expect("symlink should be created");

        let result =
            discover_files(&ScanConfig::new(temp.path())).expect("discovery should succeed");

        // The legitimate file is still discovered.
        let files = result
            .files
            .iter()
            .map(|path| normalize_path(path.strip_prefix(temp.path()).unwrap()))
            .collect::<Vec<_>>();
        assert!(files.iter().any(|path| path == "real.ts"));

        // No discovered path resolves to /etc/passwd.
        assert!(!result.files.iter().any(|path| {
            path.canonicalize()
                .map(|canonical| canonical == std::path::Path::new("/etc/passwd"))
                .unwrap_or(false)
        }));

        // The symlink itself is recorded as Skipped(Symlink) — never read.
        let skipped_link = result
            .skipped
            .iter()
            .find(|file| file.path == "escape.ts")
            .expect("symlink entry should be present in skipped list");
        assert_eq!(skipped_link.skipped_reason, Some(SkippedReason::Symlink));

        // And /etc/passwd's contents do not appear anywhere in the
        // result (defence-in-depth: discovery never reads file bytes,
        // but make the expectation explicit).
        let serialized = format!("{:?}", result);
        assert!(!serialized.contains("root:"));
    }

    #[test]
    fn discovers_supported_files_and_skips_known_boundaries() {
        let temp = tempdir().expect("tempdir should be created");
        fs::create_dir_all(temp.path().join("src")).expect("src dir should be created");
        fs::create_dir_all(temp.path().join("node_modules/pkg"))
            .expect("node_modules dir should be created");
        fs::write(temp.path().join("src/app.ts"), "const ok = true;")
            .expect("source file should be written");
        fs::write(
            temp.path().join("node_modules/pkg/index.ts"),
            "const vendor = true;",
        )
        .expect("vendor file should be written");
        fs::write(temp.path().join("Cargo.lock"), "lockfile").expect("lockfile should be written");
        fs::write(temp.path().join(".env"), "SESSION_TOKEN=secret")
            .expect("env file should be written");
        fs::write(temp.path().join("README.md"), "docs").expect("readme should be written");

        let result =
            discover_files(&ScanConfig::new(temp.path())).expect("discovery should succeed");

        let files = result
            .files
            .iter()
            .map(|path| normalize_path(path.strip_prefix(temp.path()).unwrap()))
            .collect::<Vec<_>>();
        assert!(files.iter().any(|path| path == "src/app.ts"));

        assert!(result.skipped.iter().any(|file| file.path == "Cargo.lock"
            && file.skipped_reason == Some(SkippedReason::Excluded)));
        assert!(
            result.skipped.iter().any(|file| file.path == ".env"
                && file.skipped_reason == Some(SkippedReason::SensitivePath))
        );
        assert!(result.skipped.iter().any(|file| file.path == "README.md"
            && file.skipped_reason == Some(SkippedReason::Unsupported)));
        let all_paths = result
            .files
            .iter()
            .map(|path| normalize_path(path.strip_prefix(temp.path()).unwrap()))
            .chain(result.skipped.iter().map(|file| file.path.clone()))
            .collect::<Vec<_>>();
        assert!(!all_paths.iter().any(|path| path.contains("node_modules")));
    }

    #[test]
    fn respects_gitignore_files() {
        let temp = tempdir().expect("tempdir should be created");
        fs::create_dir(temp.path().join(".git")).expect("git dir should be created");
        fs::write(temp.path().join(".gitignore"), "ignored.ts\n")
            .expect("gitignore should be written");
        fs::write(temp.path().join("ignored.ts"), "const ignored = true;")
            .expect("ignored file should be written");
        fs::write(temp.path().join("kept.ts"), "const kept = true;")
            .expect("kept file should be written");

        let result =
            discover_files(&ScanConfig::new(temp.path())).expect("discovery should succeed");
        let all_paths = result
            .files
            .iter()
            .map(|path| normalize_path(path.strip_prefix(temp.path()).unwrap()))
            .chain(result.skipped.iter().map(|file| file.path.clone()))
            .collect::<Vec<_>>();

        assert!(all_paths.iter().any(|path| path == "kept.ts"));
        assert!(!all_paths.iter().any(|path| path == "ignored.ts"));
    }

    #[test]
    fn include_and_exclude_patterns_are_repo_relative() {
        let temp = tempdir().expect("tempdir should be created");
        fs::create_dir_all(temp.path().join("src")).expect("src dir should be created");
        fs::create_dir_all(temp.path().join("test")).expect("test dir should be created");
        fs::write(temp.path().join("src/app.ts"), "const app = true;")
            .expect("source file should be written");
        fs::write(temp.path().join("test/app.test.ts"), "const test = true;")
            .expect("test file should be written");

        let mut config = ScanConfig::new(temp.path());
        config.set_include_patterns(vec!["src/**/*.ts".to_string()]);
        config.add_exclude_patterns(vec!["**/*.test.ts".to_string()]);

        let result = discover_files(&config).expect("discovery should succeed");
        let files = result
            .files
            .iter()
            .map(|path| normalize_path(path.strip_prefix(temp.path()).unwrap()))
            .collect::<Vec<_>>();

        assert_eq!(files, vec!["src/app.ts"]);
        assert!(
            result
                .skipped
                .iter()
                .any(|file| file.path == "test/app.test.ts"
                    && file.skipped_reason == Some(SkippedReason::Excluded))
        );
    }
}
