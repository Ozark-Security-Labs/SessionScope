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
        "  sessionscope scan [--path PATH] [--include PATTERN] [--exclude PATTERN] [--max-file-size BYTES] [--format FORMAT] [--output PATH] [--mode advisory|enforce] [--fail-severity high|medium|low|info] [--fail-category CATEGORY] [--include-finding-id ID] [--exclude-finding-id ID] [--baseline PATH]\n",
        "  sessionscope explain FINDING_ID\n",
        "  sessionscope baseline create\n",
        "  sessionscope diff <base...head>\n",
        "  sessionscope version\n\n",
        "Scan filters use repository-relative glob patterns. --include and --exclude may be repeated or comma-separated.\n\n",
        "Formats: markdown, json, sarif, github-summary\n",
        "Enforce mode exits nonzero after reports are written when findings match policy.\n"
    ));
}
