pub mod baseline;
pub mod diff;
pub mod evaluate;
pub mod explain;
pub mod init;
pub mod policy;
pub mod scan;

use std::error::Error;

use sessionscope_core::CapabilityArea;

/// CLI subcommand result.
///
/// Type-erased errors (`Box<dyn Error>`) are used here because the CLI is the
/// outer boundary: errors only need to be Display-formatted onto stderr and a
/// nonzero exit code chosen. Different subcommands surface very different
/// failure modes (I/O, JSON parse, policy enforcement, scan pipeline), and a
/// trait object lets each one bubble up its native error type with `?`
/// without forcing every layer through a shared enum.
///
/// If any of these subcommand entry points is ever exposed as a library API
/// (e.g. re-used from another binary or invoked programmatically), define a
/// typed `CliError` enum with explicit variants so callers can match on the
/// failure mode instead of relying on string formatting.
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
        Some("evaluate") => evaluate::run(&args[1..]),
        Some("cookies") => scan::run_capability(&args[1..], CapabilityArea::Cookies),
        Some("claims") => scan::run_capability(&args[1..], CapabilityArea::Claims),
        Some("logout") => scan::run_capability(&args[1..], CapabilityArea::Logout),
        Some("refresh") => scan::run_capability(&args[1..], CapabilityArea::Refresh),
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
        "  sessionscope evaluate REPORT.json [--mode advisory|enforce] [--fail-severity high|medium|low|info] [--fail-category CATEGORY] [--include-finding-id ID] [--exclude-finding-id ID] [--baseline PATH]\n",
        "  sessionscope cookies [scan options]\n",
        "  sessionscope claims [scan options]\n",
        "  sessionscope logout [scan options]\n",
        "  sessionscope refresh [scan options]\n",
        "  sessionscope explain FINDING_ID --report REPORT.json\n",
        "  sessionscope baseline create --from REPORT.json [--output BASELINE.json]\n",
        "  sessionscope diff --baseline BASELINE.json --current REPORT.json [--format json|markdown] [--output PATH]\n",
        "  sessionscope version\n\n",
        "cookies, claims, logout, and refresh are focused views over sessionscope scan and support markdown or json output.\n",
        "Scan filters use repository-relative glob patterns. --include and --exclude may be repeated or comma-separated.\n\n",
        "Formats: markdown, json, sarif, github-summary. Use comma-separated formats with --output-dir DIR to write multiple reports from one scan.\n",
        "Enforce mode exits nonzero after reports are written when findings match policy.\n"
    ));
}
