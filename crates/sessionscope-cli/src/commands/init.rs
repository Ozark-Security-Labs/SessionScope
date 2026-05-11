use std::fs;
use std::path::Path;

use crate::commands::CommandResult;
use crate::project_config::{CONFIG_FILE_NAME, DEFAULT_CONFIG};

pub fn run(args: &[String]) -> CommandResult {
    let force = args.iter().any(|arg| arg == "--force");
    let config_path = Path::new(CONFIG_FILE_NAME);

    if config_path.exists() && !force {
        return Err("sessionscope.toml already exists; pass --force to overwrite".into());
    }

    fs::write(config_path, DEFAULT_CONFIG)?;
    println!("created {CONFIG_FILE_NAME}");
    Ok(())
}
