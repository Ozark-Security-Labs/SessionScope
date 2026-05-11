use crate::commands::CommandResult;

pub fn run(args: &[String]) -> CommandResult {
    match args.first().map(String::as_str) {
        Some("create") => {
            println!("baseline create is scaffolded; baseline persistence is not implemented yet");
            Ok(())
        }
        _ => Err("usage: sessionscope baseline create".into()),
    }
}
