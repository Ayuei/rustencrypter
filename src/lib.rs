use std::fs;
use std::fmt;
use std::env;
use std::error;
use std::io::prelude::*;
use std::path::{PathBuf, Path};
use rand::prelude::*;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};
use aes_gcm::aead::generic_array::typenum::consts::U12;
use structopt::{StructOpt, clap::ArgGroup};
use walkdir::WalkDir;

// Parse arguments for the CLI
#[derive(StructOpt, Debug)]
#[structopt(group = ArgGroup::with_name("action").required(true))]
pub struct Opt {
    #[structopt(short, long, group = "action", help = "Encrypt a file or directory")]
    pub encrypt: bool,

    #[structopt(short, long, group = "action", help = "Decrypt an encrypted file or directory")]
    pub decrypt: bool,

    #[structopt(short, long, parse(from_os_str))]
    key: Option<PathBuf>,

    #[structopt(short, long, help = "Use AES-GCM 256 bit encryption instead")]
    aesgcm256: bool,

    #[structopt(name = "input file or directory", parse(from_os_str))]
    pub infile: PathBuf,
}

// Creating our custom Error as aes_gcm doesn't implement std:Error
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

/// Generate a fresh key with a CSPRNG
/// We can determine keylength be specified boolean
pub fn generate_key(key256: bool) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key: Vec<u8> = {
        if key256 {
            vec![0; 32]
        } else {
            vec![0; 16]
        }
    };

    rng.fill_bytes(&mut key);
    key
}

/// Generate a fresh nonce for every encryption from CSPRNG
pub fn generate_nonce() -> GenericArray<u8, U12> {
    let mut rng = rand::thread_rng();
    let mut nonce = [0; 12];
    rng.fill_bytes(&mut nonce);
    *GenericArray::from_slice(&nonce) // 96-bits; unique per message
}

/// Generate a key to given file if it doesn't exist
pub fn check_key_file(file: &PathBuf, key256: bool) -> Vec<u8> {
    if Path::new(&file).exists() {
        // Load old key
        fs::read(file).unwrap()
    } else {
        // Create a new key
        let mut file = fs::File::create(&file).unwrap();
        let key = generate_key(key256);
        file.write_all(key.to_vec().as_slice()).unwrap();
        key
    }
}

// TODO decouple OPT dependency from the function and simply parse it from main
/// Run an encryption or decryption task from main function
pub fn run(
    opts: Opt, 
    cb: &dyn Fn(Vec<u8>, &Vec<u8>) -> Result<Vec<u8>, Box<dyn error::Error>> 
) -> Result<(), Box<dyn error::Error>> {

    let key = match opts.key {
        // Key path is supplied, check if it exists, if not, create it
        Some(key_file) => check_key_file(&key_file, opts.aesgcm256),
        None => {
            // Key path not supplied, default to CWD
            let mut cwd = env::current_dir()?;
            cwd.push("key");
            check_key_file(&cwd, opts.aesgcm256)
        }
    };

    if opts.infile.is_dir(){
        // Walk through directories for any files
        for entry in WalkDir::new(&opts.infile).into_iter().filter_map(|e| e.ok()).filter(|e| e.path().is_file()) {
            println!("Consuming {}", entry.path().display()); // alert user what we're doing (loading bar may be more appropriate)
            fs::write(entry.path(), cb(fs::read(entry.path())?, &key)?)?
        }
    } else {
        fs::write(&opts.infile, cb(fs::read(&opts.infile)?, &key)?)?
    };

    Ok(())
}

/// Encryption callback
pub fn encrypt_cb(contents: Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let nonce = generate_nonce();
    let mut ciphertext = {
        if key.len() == 32 {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_slice()));
            cipher.encrypt(&nonce, contents.as_ref()).or(Err(Box::new(CryptoError::EncryptFail)))?
        } else {
            let cipher = Aes128Gcm::new(GenericArray::from_slice(key.as_slice()));
            cipher.encrypt(&nonce, contents.as_ref()).or(Err(Box::new(CryptoError::EncryptFail)))?
        }
    };

    ciphertext.append(&mut nonce.to_vec());
    Ok(ciphertext)
}

/// Decryption callback
pub fn decrypt_cb(contents: Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let len = contents.len();
    let nonce = GenericArray::from_slice(&contents[len-12..len]);
    let plaintext = {
        if key.len() == 32 {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(key.as_slice()));
            cipher.decrypt(nonce, contents[0..len-12].as_ref()).or(Err(Box::new(CryptoError::DecryptFail)))?
        } else {
            let cipher = Aes128Gcm::new(GenericArray::from_slice(key.as_slice()));
            cipher.decrypt(nonce, contents[0..len-12].as_ref()).or(Err(Box::new(CryptoError::DecryptFail)))?
        }
    };
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn encrypt_decrypt(key: &Vec<u8>, nonce: GenericArray<u8, U12>) -> Vec<u8> {
        let cipher = Aes128Gcm::new(GenericArray::from_slice(key.as_ref()));
        let contents = b"plaintext message";

        let mut ciphertext = cipher.encrypt(&nonce, contents.as_ref()).unwrap();
        ciphertext.append(&mut nonce.to_vec());
        let len = ciphertext.len();
        let nonce_size = nonce.len();

        let nonce = GenericArray::from_slice(&ciphertext[len-nonce_size..len]);
        cipher.decrypt(&nonce, ciphertext[0..len-nonce_size].as_ref()).unwrap()
    }

    #[test]
    fn check_key_gen() {
        let key = generate_key(false);
        let nonce = *GenericArray::from_slice(&[0; 12]);

        assert_eq!(encrypt_decrypt(&key, nonce), b"plaintext message");
    }

    #[test]
    fn check_nonce_gen() {
        let key = vec![0; 16];
        let nonce = generate_nonce();

        assert_eq!(encrypt_decrypt(&key, nonce), b"plaintext message");
    }

    #[test]
    fn check_key_file_exists() {
        let mut file = NamedTempFile::new().unwrap(); 
        let key = generate_key(false);
        file.write_all(key.to_vec().as_slice()).unwrap();

        let out_key = check_key_file(&file.path().into(), false);

        assert_eq!(key, out_key)
    }

    #[test]
    fn check_run_encrypt() {
        let mut file = fs::File::create("test").unwrap(); 
        let mut key_file = fs::File::create("test_key").unwrap(); 

        // Write random stuff to file
        let key = generate_key(false);
        file.write_all(key.to_vec().as_slice()).unwrap();
        key_file.write_all(key.to_vec().as_slice()).unwrap();

        // Encrypt
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("test"), key: Some(PathBuf::from("test_key")), aesgcm256: false};
        run(opt, &encrypt_cb).unwrap();

        // Decrypt 
        let cipher = Aes128Gcm::new(GenericArray::from_slice(key.as_ref()));
        let ciphertext = fs::read("test").unwrap();

        let len = ciphertext.len();
        let nonce_size = 12;

        let nonce = GenericArray::from_slice(&ciphertext[len-nonce_size..len]);
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
        let key = generate_key(false);
        key_file.write_all(key.to_vec().as_slice()).unwrap();

        // Encrypt 
        println!("{}", key.len());
        let cipher = Aes128Gcm::new(GenericArray::from_slice(key.as_ref()));
        let nonce = generate_nonce();
        let mut ciphertext = cipher.encrypt(&nonce, key.as_ref()).unwrap();

        ciphertext.append(&mut nonce.to_vec());
        
        file.write_all(ciphertext.as_slice()).unwrap();

        // Decrypt 
        let opt = Opt{encrypt: false, decrypt: true, infile: PathBuf::from("test_decrypt"), key: Some(PathBuf::from("test_key_decrypt")), aesgcm256: false};
        run(opt, &decrypt_cb).unwrap();

        let result = fs::read("test_decrypt").unwrap();

        fs::remove_file("test_decrypt").unwrap();
        fs::remove_file("test_key_decrypt").unwrap();

        assert_eq!(key.to_vec(), result);
    }

    #[test]
    fn check_run_key_file_not_exists() {
        let mut file = fs::File::create("test_not_exists").unwrap(); 

        // Write random stuff to file
        let rand_msg = generate_key(false);
        file.write_all(rand_msg.to_vec().as_slice()).unwrap();
        file.flush().unwrap();

        // Encrypt
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("test_not_exists"), key: Option::None, aesgcm256: false};
        run(opt, &encrypt_cb).unwrap();

        let result = fs::read("test_not_exists").unwrap();

        // Decrypt 
        let key_data = fs::read("key").unwrap();
        println!("{}", key_data.len());
        let key = GenericArray::from_slice(&key_data);
        let cipher = Aes128Gcm::new(&key);

        let len = result.len();
        let nonce_size = 12;

        let nonce = GenericArray::from_slice(&result[len-nonce_size..len]);
        let plaintext = cipher.decrypt(nonce, result[0..len-nonce_size].as_ref()).unwrap();

        fs::remove_file("test_not_exists").unwrap();
        fs::remove_file("key").unwrap();

        assert_eq!(rand_msg.to_vec(), plaintext);
    }
    
    #[test]
    #[should_panic]
    fn check_run_infile_not_exists() {
        // Encrypt
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("file_does_not_exist"), key: Option::None, aesgcm256: false};
        let _result = run(opt, &encrypt_cb).unwrap();
    }

    #[test]
    fn check_run_encrypt_decrypt_directory() {
        let key_filename = "test_key_directory";
        let mut key_file = fs::File::create(key_filename).unwrap(); 
        let key = generate_key(false);
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
        let opt = Opt{encrypt: true, decrypt: false, infile: PathBuf::from("testdir/"), key: Some(PathBuf::from(key_filename)), aesgcm256: false};
        run(opt, &encrypt_cb).unwrap();

        let cipher = Aes128Gcm::new(GenericArray::from_slice(key.as_ref()));
        // Decrypt 
        for i in 0..5 {
            for j in 0..3 {
                let fp = format!("testdir/{}/{}/file", i.to_string(), j.to_string());
                let ciphertext = fs::read(fp).unwrap();

                let len = ciphertext.len();
                let nonce_size = 12;

                let nonce = GenericArray::from_slice(&ciphertext[len-nonce_size..len]);
                let plaintext = cipher.decrypt(nonce, ciphertext[0..len-nonce_size].as_ref()).unwrap();

                assert_eq!(key.to_vec(), plaintext);
            }
        };

        fs::remove_file(key_filename).unwrap();
        fs::remove_dir_all("testdir/").unwrap();
    }
}