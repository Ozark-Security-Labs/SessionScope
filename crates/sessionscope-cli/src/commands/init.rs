use std::fs;
use std::path::Path;

use crate::commands::CommandResult;

const DEFAULT_CONFIG: &str = concat!(
    "# SessionScope configuration\n",
    "scan_paths = [\".\"]\n",
    "formats = [\"markdown\", \"json\"]\n",
    "mode = \"advisory\"\n",
    "max_file_size_bytes = 1000000\n",
);

pub fn run(args: &[String]) -> CommandResult {
    let force = args.iter().any(|arg| arg == "--force");
    let config_path = Path::new("sessionscope.toml");

    if config_path.exists() && !force {
        return Err("sessionscope.toml already exists; pass --force to overwrite".into());
    }

    fs::write(config_path, DEFAULT_CONFIG)?;
    println!("created sessionscope.toml");
    Ok(())
}
