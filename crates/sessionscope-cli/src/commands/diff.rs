use crate::commands::CommandResult;

pub fn run(args: &[String]) -> CommandResult {
    let range = args
        .first()
        .ok_or("missing diff range such as main...HEAD")?;

    println!("diff is scaffolded; comparison is not implemented yet: {range}");
    Ok(())
}
