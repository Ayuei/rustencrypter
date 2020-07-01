use rustencrypter::{run, Opt, encrypt_cb, decrypt_cb};
use std::process;
use std::error;
use structopt::StructOpt;

fn main() {
    let opt = Opt::from_args();

    let cb: &dyn Fn(Vec<u8>, &Vec<u8>) -> Result<Vec<u8>, Box<dyn error::Error>>  = {
        if opt.encrypt {
            &encrypt_cb
        } else {
            &decrypt_cb
        }
    };

    match run(opt, cb) {
        Ok(data) => data,
        Err(error) => {
            println!("{:?}", error);
            process::exit(1);
        }
    };
}