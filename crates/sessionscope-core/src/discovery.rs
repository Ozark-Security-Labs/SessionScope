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
        .parents(true);

    for entry in builder.build() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let path = entry.path();

        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let relative_path = relative_path(&config.root, path);
        let language = classify_language(path);

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

    files.sort_by_key(|path| normalize_path(&relative_path(&config.root, path)));
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

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
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
        assert!(
            result
                .skipped
                .iter()
                .any(|file| file.path == "node_modules/pkg/index.ts"
                    && file.skipped_reason == Some(SkippedReason::Excluded))
        );
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
