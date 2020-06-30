use crypto::{run, Opt};
use std::process;
use structopt::StructOpt;

fn main() {
    let opt = Opt::from_args();

    match run(opt) {
        Ok(data) => data,
        Err(error) => {
            println!("{:?}", error);
            process::exit(1);
        }
    };
}