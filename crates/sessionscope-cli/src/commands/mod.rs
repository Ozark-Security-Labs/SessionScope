pub mod baseline;
pub mod diff;
pub mod explain;
pub mod init;
pub mod scan;

use std::error::Error;

pub type CommandResult = Result<(), Box<dyn Error>>;

pub fn run(args: impl IntoIterator<Item = String>) -> CommandResult {
    let args = args.into_iter().collect::<Vec<_>>();
    let command = args.first().map(String::as_str);

    match command {
        None | Some("--help" | "-h" | "help") => {
            print_help();
            Ok(())
        }
        Some("--version" | "-V" | "version") => {
            println!("sessionscope {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("init") => init::run(&args[1..]),
        Some("scan") => scan::run(&args[1..]),
        Some("explain") => explain::run(&args[1..]),
        Some("baseline") => baseline::run(&args[1..]),
        Some("diff") => diff::run(&args[1..]),
        Some(_) => Err("unknown command; run `sessionscope --help`".into()),
    }
}

fn print_help() {
    println!(concat!(
        "SessionScope\n\n",
        "Usage:\n",
        "  sessionscope init [--force]\n",
        "  sessionscope scan [--path PATH] [--format FORMAT] [--output PATH]\n",
        "  sessionscope explain FINDING_ID\n",
        "  sessionscope baseline create\n",
        "  sessionscope diff <base...head>\n",
        "  sessionscope version\n\n",
        "Formats: markdown, json, sarif, github-summary\n"
    ));
}
