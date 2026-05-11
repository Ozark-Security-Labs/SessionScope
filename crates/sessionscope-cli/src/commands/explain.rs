use crate::commands::CommandResult;

pub fn run(args: &[String]) -> CommandResult {
    let finding_id = args
        .first()
        .ok_or("missing FINDING_ID for explain command")?;

    println!("explain is scaffolded; finding lookup is not implemented yet: {finding_id}");
    Ok(())
}
