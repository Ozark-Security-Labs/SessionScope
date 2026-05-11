use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::ScanConfig;

pub fn discover_files(config: &ScanConfig) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    visit_dir(&config.root, config, &mut files)?;
    files.sort_by_key(|path| normalize_path(path));
    Ok(files)
}

fn visit_dir(dir: &Path, config: &ScanConfig, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if should_skip_dir(dir, config) {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            visit_dir(&path, config, files)?;
        } else if file_type.is_file() && should_include_file(&path, config) {
            files.push(path);
        }
    }

    Ok(())
}

fn should_skip_dir(path: &Path, config: &ScanConfig) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| config.exclude_dirs.iter().any(|excluded| excluded == name))
}

fn should_include_file(path: &Path, config: &ScanConfig) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            config
                .include_extensions
                .iter()
                .any(|included| included == extension)
        })
}

pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
