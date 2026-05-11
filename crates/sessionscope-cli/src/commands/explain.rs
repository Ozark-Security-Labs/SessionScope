use crate::commands::CommandResult;

pub fn run(args: &[String]) -> CommandResult {
    args.first()
        .ok_or("missing FINDING_ID for explain command")?;

    println!("explain is scaffolded; finding lookup is not implemented yet");
    Ok(())
}
