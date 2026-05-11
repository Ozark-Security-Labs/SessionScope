mod commands;

use std::process::ExitCode;

fn main() -> ExitCode {
    match commands::run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sessionscope: {error}");
            ExitCode::FAILURE
        }
    }
}
