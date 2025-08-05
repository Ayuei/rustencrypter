use rustencrypter::run;
use std::process;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = run(clap::Parser::parse()) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
    Ok(())
}
