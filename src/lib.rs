use std::fs;
use std::fmt;
use std::env;
use std::error;
use std::io::prelude::*;
use std::path::{PathBuf, Path};
use rand::prelude::*;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, NewAead, generic_array};
use aes_gcm::aead::generic_array::typenum::consts::{U12, U16};
use structopt::{StructOpt, clap::ArgGroup};
use walkdir::WalkDir;

#[derive(StructOpt, Debug)]
#[structopt(group = ArgGroup::with_name("action").required(true))]
pub struct Opt {
    #[structopt(short, long, group = "action")]
    encrypt: bool,

    #[structopt(short, long, group = "action")]
    decrypt: bool,

    #[structopt(short, long, parse(from_os_str))]
    key: Option<PathBuf>,

    #[structopt(name = "input file", parse(from_os_str))]
    pub infile: PathBuf,
}

#[derive(Debug, Clone)]
enum CryptoError {
    EncryptFail,
    DecryptFail,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::EncryptFail => write!(f, "Encryption Failed"),
            // This is a wrapper, so defer to the underlying types' implementation of `fmt`.
            CryptoError::DecryptFail => write!(f, "Decryption Failed"),
        }
    }
}

impl error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

pub fn generate_key() -> generic_array::GenericArray<u8, U16> {
    let mut key = [0; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);
    *generic_array::GenericArray::from_slice(&key)
}

pub fn generate_nonce() -> generic_array::GenericArray<u8, U12> {
    let mut rng = rand::thread_rng();
    let mut nonce = [0; 12];
    rng.fill_bytes(&mut nonce);
    *generic_array::GenericArray::from_slice(&nonce) // 96-bits; unique per message
}

pub fn check_key_file(file: &PathBuf) -> generic_array::GenericArray<u8, U16> {
    if Path::new(&file).exists() {
        *generic_array::GenericArray::from_slice(&fs::read(file).unwrap())
    } else {
        let mut file = fs::File::create(&file).unwrap();
        let key = generate_key();
        file.write_all(key.to_vec().as_slice()).unwrap();
        key
    }
}

// TODO Do this with callbacks instead.
pub fn run(opts: Opt) -> Result<(), Box<dyn error::Error>> {
    let key = match opts.key {
        Some(key_file) => check_key_file(&key_file),
        None => {
            // Key file not supplied, default to CWD?
            let mut cwd = env::current_dir()?;
            cwd.push("key");
            check_key_file(&cwd)
        }
    };

    let cipher = Aes128Gcm::new(&key);

    if opts.infile.is_dir(){
        for entry in WalkDir::new(opts.infile).into_iter().filter_map(|e| e.ok()).filter(|e| e.path().is_file()) {
            println!("Consuming {}", entry.path().display());
            fs::write(entry.path(), process(opts.encrypt, fs::read(entry.path())?, &cipher)?)?
        }
    } else {
        fs::write(opts.infile.clone(), process(opts.encrypt, fs::read(opts.infile)?, &cipher)?)?
    };

    Ok(())
}

// TODO Do this with callbacks instead.
pub fn process(encrypt: bool, contents: Vec<u8>, cipher: &Aes128Gcm) -> Result<Vec<u8>, Box<dyn error::Error>> {
    if encrypt {
        let nonce = generate_nonce();
        let mut ciphertext = cipher.encrypt(&nonce, contents.as_ref()).or(Err(Box::new(CryptoError::EncryptFail)))?;
        ciphertext.append(&mut nonce.to_vec());
        Ok(ciphertext)
    } else {
        let len = contents.len();
        let nonce = generic_array::GenericArray::from_slice(&contents[len-12..len]);
        let plaintext = cipher.decrypt(nonce, contents[0..len-12].as_ref()).or(Err(Box::new(CryptoError::DecryptFail)))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn encrypt_decrypt(key: generic_array::GenericArray<u8, U16>, nonce: generic_array::GenericArray<u8, U12>) -> Vec<u8> {
        let cipher = Aes128Gcm::new(&key);
        let contents = b"plaintext message";

        let mut ciphertext = cipher.encrypt(&nonce, contents.as_ref()).unwrap();
        ciphertext.append(&mut nonce.to_vec());
        let len = ciphertext.len();
        let nonce_size = nonce.len();

        let nonce = generic_array::GenericArray::from_slice(&ciphertext[len-nonce_size..len]);
        cipher.decrypt(&nonce, ciphertext[0..len-nonce_size].as_ref()).unwrap()
    }

    #[test]
    fn check_key_gen() {
        let key = generate_key();
        let nonce = *generic_array::GenericArray::from_slice(&[0; 12]);

        assert_eq!(encrypt_decrypt(key, nonce), b"plaintext message");
    }

    #[test]
    fn check_nonce_gen() {
        let key= *generic_array::GenericArray::from_slice(&[0; 16]);
        let nonce = generate_nonce();

        assert_eq!(encrypt_decrypt(key, nonce), b"plaintext message");
    }

    #[test]
    fn check_key_file_exists() {
        let mut file = NamedTempFile::new().unwrap(); 
        let key = generate_key();
        file.write_all(key.to_vec().as_slice()).unwrap();

        let out_key = check_key_file(&file.path().into());

        assert_eq!(key, out_key)
    }
    
    #[test]
    fn check_key_file_not_exists() {
        let mut cwd = env::current_dir().unwrap();
        cwd.push("key");

        let key = check_key_file(&cwd);
        let contents = *generic_array::GenericArray::from_slice(fs::read(&cwd).unwrap().as_slice());

        fs::remove_file(cwd.as_path()).unwrap();
        assert_eq!(key, contents)
    }

    #[test]
    fn check_run_encrypt() {
        let mut file = fs::File::create("test").unwrap(); 
        let mut key_file = fs::File::create("test_key").unwrap(); 

        // Write random stuff to file
        let key = generate_key();
        file.write_all(key.to_vec().as_slice()).unwrap();
        key_file.write_all(key.to_vec().as_slice()).unwrap();

        // Encrypt
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("test"), key: Some(PathBuf::from("test_key"))};
        run(opt).unwrap();

        // Decrypt 
        let cipher = Aes128Gcm::new(&key);
        let ciphertext = fs::read("test").unwrap();

        let len = ciphertext.len();
        let nonce_size = 12;

        let nonce = generic_array::GenericArray::from_slice(&ciphertext[len-nonce_size..len]);
        let plaintext = cipher.decrypt(nonce, ciphertext[0..len-nonce_size].as_ref()).unwrap();

        fs::remove_file("test").unwrap();
        fs::remove_file("test_key").unwrap();

        assert_eq!(key.to_vec(), plaintext);
    }
    #[test]
    fn check_run_decrypt() {
        let mut file = fs::File::create("test_decrypt").unwrap(); 
        let mut key_file = fs::File::create("test_key_decrypt").unwrap(); 

        // Generate key file 
        let key = generate_key();
        key_file.write_all(key.to_vec().as_slice()).unwrap();

        // Encrypt 
        let cipher = Aes128Gcm::new(&key);
        let nonce = generate_nonce();
        let mut ciphertext = cipher.encrypt(&nonce, key.as_ref()).unwrap();

        ciphertext.append(&mut nonce.to_vec());
        
        file.write_all(ciphertext.as_slice()).unwrap();

        // Decrypt 
        let opt = Opt{encrypt: false, decrypt: true, infile: PathBuf::from("test_decrypt"), key: Some(PathBuf::from("test_key_decrypt"))};
        run(opt).unwrap();

        let result = fs::read("test_decrypt").unwrap();

        fs::remove_file("test_decrypt").unwrap();
        fs::remove_file("test_key_decrypt").unwrap();

        assert_eq!(key.to_vec(), result);
    }

    #[test]
    fn check_run_key_file_not_exists() {
        let mut file = fs::File::create("test_not_exists").unwrap(); 

        // Write random stuff to file
        let rand_msg= generate_key();
        file.write_all(rand_msg.to_vec().as_slice()).unwrap();
        file.flush().unwrap();

        // Encrypt
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("test_not_exists"), key: Option::None};
        run(opt).unwrap();

        let result = fs::read("test_not_exists").unwrap();

        // Decrypt 
        let key_data = fs::read("key").unwrap();
        let key = generic_array::GenericArray::from_slice(&key_data);
        let cipher = Aes128Gcm::new(&key);

        let len = result.len();
        let nonce_size = 12;

        let nonce = generic_array::GenericArray::from_slice(&result[len-nonce_size..len]);
        let plaintext = cipher.decrypt(nonce, result[0..len-nonce_size].as_ref()).unwrap();

        fs::remove_file("test_not_exists").unwrap();
        fs::remove_file("key").unwrap();

        assert_eq!(rand_msg.to_vec(), plaintext);
    }
    
    #[test]
    #[should_panic]
    fn check_run_infile_not_exists() {
        // Encrypt
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("file_does_not_exist"), key: Option::None};
        let _result = run(opt).unwrap();
    }

    #[test]
    fn check_run_encrypt_decrypt_directory() {
        let key_filename = "test_key_directory";
        let mut key_file = fs::File::create(key_filename).unwrap(); 
        let key = generate_key();
        key_file.write_all(key.to_vec().as_slice()).unwrap();

        for i in 0..5 {
            for j in 0..3 {
                let mut fp = format!("testdir/{}/{}/", i.to_string(), j.to_string());
                fs::create_dir_all(&fp).unwrap();
                fp.push_str("file");
                fs::write(&fp, key.to_vec().as_slice()).unwrap();
            }
        };

        // Encrypt
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("testdir/"), key: Some(PathBuf::from(key_filename))};
        run(opt).unwrap();

        let cipher = Aes128Gcm::new(&key);
        // Decrypt 
        for i in 0..5 {
            for j in 0..3 {
                let fp = format!("testdir/{}/{}/file", i.to_string(), j.to_string());
                let ciphertext = fs::read(fp).unwrap();

                let len = ciphertext.len();
                let nonce_size = 12;

                let nonce = generic_array::GenericArray::from_slice(&ciphertext[len-nonce_size..len]);
                let plaintext = cipher.decrypt(nonce, ciphertext[0..len-nonce_size].as_ref()).unwrap();

                assert_eq!(key.to_vec(), plaintext);
            }
        };

        fs::remove_file(key_filename).unwrap();
        fs::remove_dir_all("testdir/").unwrap();
    }
}