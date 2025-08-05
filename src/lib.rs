use aes_gcm::aead::consts::U5;
use aes_gcm::aead::stream::{NewStream, StreamPrimitive};
use aes_gcm::aes::cipher::ArrayLength;
use aes_gcm::{AeadCore, AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use clap::{Parser, Subcommand};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::TryRngCore;
use rayon::prelude::*;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::ops::Sub;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use thiserror::Error;
use walkdir::WalkDir;

const AES_128_KEY_SIZE: usize = 16;
const AES_256_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 7; // 96-bits is used for AES-GCM
const AES_TAG_SIZE: usize = 16; // 128 bit is used for authentication tag
const ENCRYPT_BUFFER_SIZE: usize = 8192; // 8KB buffer
const DECRYPT_BLOCK_SIZE: usize = ENCRYPT_BUFFER_SIZE + AES_TAG_SIZE;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Cryptography error, either the data has been tampered with or the file is not encrypted at all!")]
    Crypto(#[from] aes_gcm::Error),
    #[error("Invalid key length: expected {expected}, got {actual}. Did you mix up your AES-256 and AES-128 keys?")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Could not persist temporary file: {0}")]
    CouldNotPersist(#[from] tempfile::PersistError),
    #[error("Could not recursively parse directories: {0}")]
    WalkDir(#[from] walkdir::Error),
    #[error("Template error for progress bar: {0}")]
    TemplateError(#[from] indicatif::style::TemplateError),
    #[error("Temporary file cannot be created due to:{0}")]
    TempFileError(#[from] io::IntoInnerError<BufWriter<NamedTempFile>>),
}

// Result alias for convenience
type Result<T> = std::result::Result<T, AppError>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[arg(
        short,
        long,
        global = true,
        value_name = "FILE",
        help = "Path to the encryption key file. If not provided, defaults to './key'"
    )]
    pub key: Option<PathBuf>,

    #[arg(
        short,
        long,
        global = true,
        help = "Use 256-bit AES-GCM instead of 128-bit"
    )]
    pub aes256: bool,

    #[arg(
        short,
        long,
        global = true,
        help = "Number of times to repeat encryption or decryption.",
        default_value_t = 1
    )]
    pub repeat: usize,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Encrypt a file or directory
    Encrypt {
        #[arg(help = "Input file or directory to process")]
        path: PathBuf,
    },
    /// Decrypt a file or directory
    Decrypt {
        #[arg(help = "Input file or directory to process")]
        path: PathBuf,
    },
}

impl Command {
    fn get_path(&self) -> &PathBuf {
        match self {
            Command::Encrypt { path } => path,
            Command::Decrypt { path } => path,
        }
    }
}

/// Generates a cryptographically secure random key.
fn generate_key(size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    OsRng
        .try_fill_bytes(&mut key)
        .expect("Could not securely fill the bytes of the key. Is this a new server?");
    key
}

/// Reads a key from a file, or creates one if it doesn't exist.
fn get_or_create_key(key_path: &Path, key_size: usize) -> Result<Vec<u8>> {
    if key_path.exists() {
        let key = std::fs::read(key_path)?;
        if key.len() != key_size {
            return Err(AppError::InvalidKeyLength {
                expected: key_size,
                actual: key.len(),
            });
        }
        Ok(key)
    } else {
        println!(
            "Key file not found. Generating new key at: {}",
            key_path.display()
        );
        let key = generate_key(key_size);
        std::fs::write(key_path, &key)?;
        Ok(key)
    }
}

// Encrypts stream using AES streaming encryption, uses BUFFER_SIZE to encrypt plaintext + includes authentication tag 128 bits
fn encrypt_stream<A>(cipher: A, source: &mut impl Read, dest: &mut impl Write) -> Result<()>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .expect("Could not securely fill the bytes of the nonce. Is this a new server?");
    dest.write_all(&nonce_bytes)?;

    let nonce = Nonce::from_slice(&nonce_bytes[..]);

    let mut position = 0;

    let mut buffer = [0u8; ENCRYPT_BUFFER_SIZE];
    let encryptor = aes_gcm::aead::stream::StreamBE32::from_aead(cipher, nonce);

    loop {
        let bytes_read = source.read(&mut buffer)?;

        let block = &buffer[..bytes_read];
        if bytes_read < ENCRYPT_BUFFER_SIZE {
            // This is the last block
            let ciphertext = encryptor.encrypt(position, true, block)?;
            dest.write_all(&ciphertext)?;
            break;
        } else {
            // This is a full block, might not be the last
            let ciphertext = encryptor.encrypt(position, false, block)?;
            dest.write_all(&ciphertext)?;
        }

        position += 1;
    }

    Ok(())
}

// Decrypts stream using AES streaming encryption, uses BLOCK_SIZE to decrypt cyphertext + authentication tag
fn decrypt_stream<A>(cipher: A, source: &mut impl Read, dest: &mut impl Write) -> Result<()>
where
    A: AeadInPlace,
    A::NonceSize: Sub<U5>,
    <<A as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    source.read_exact(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes[..]);

    let mut position = 0;

    // Tag size is U16
    let mut buffer = [0u8; DECRYPT_BLOCK_SIZE];
    let encryptor = aes_gcm::aead::stream::StreamBE32::from_aead(cipher, nonce);

    loop {
        let bytes_read = source.read(&mut buffer)?;

        let block = &buffer[..bytes_read];
        if bytes_read < DECRYPT_BLOCK_SIZE {
            // This is the last block
            let ciphertext = encryptor.decrypt(position, true, block)?;
            dest.write_all(&ciphertext)?;
            break;
        } else {
            // This is a full block, might not be the last
            let ciphertext = encryptor.decrypt(position, false, block)?;
            dest.write_all(&ciphertext)?;
        }

        position += 1;
    }

    Ok(())
}

// Encrypt or decrypt stream from reader
fn process_stream(
    command: Command,
    source: &mut impl Read,
    dest: &mut impl Write,
    key: &[u8],
    aes256: bool,
) -> Result<()> {
    match command {
        Command::Encrypt { path: _ } => {
            if aes256 {
                let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                encrypt_stream(cipher, source, dest)
            } else {
                let cipher = Aes128Gcm::new_from_slice(key).unwrap();
                encrypt_stream(cipher, source, dest)
            }
        }
        Command::Decrypt { path: _ } => {
            if aes256 {
                let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                decrypt_stream(cipher, source, dest)
            } else {
                let cipher = Aes128Gcm::new_from_slice(key).unwrap();
                decrypt_stream(cipher, source, dest)
            }
        }
    }
}

/// Processes a single file: encrypts or decrypts it safely using a temporary file.
fn process_file(path: &Path, command: Command, key: &[u8], aes256: bool) -> Result<()> {
    let mut source_file = File::open(path)?;

    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = BufWriter::new(NamedTempFile::new_in(parent_dir)?);

    let result = process_stream(command, &mut source_file, &mut temp_file, key, aes256);

    if result.is_ok() {
        temp_file.into_inner()?.persist(path)?;
    }

    result
}

/// Main entry point for the application logic.
pub fn run(cli: Cli) -> Result<()> {
    let (key_size, default_key_name) = if cli.aes256 {
        println!("Big Key");
        (AES_256_KEY_SIZE, "secret_key_256")
    } else {
        (AES_128_KEY_SIZE, "secret_key_128")
    };

    // Determine the default key path in an OS-independent way.
    let default_key_path = || {
        // dirs::data_dir() returns the conventional location for app data.
        // Linux:   ~/.local/share
        // macOS:   ~/Library/Application Support
        // Windows: C:\Users\<user>\AppData\Roaming
        dirs::data_dir()
            .map(|mut path| {
                // It's crucial to create a subdirectory for your application
                // to avoid polluting the user's data directory.
                path.push("rust_encrypter");

                // Create the application's data directory if it doesn't exist.
                // create_dir_all is idempotent, so it's safe to call every time.
                if let Err(e) = std::fs::create_dir_all(&path) {
                    // If we can't create the directory, we can't store the key.
                    // We'll fall back to the local directory, but print a warning.
                    eprintln!("Warning: Could not create data directory at {}: {}. Falling back to local 'key' file.", path.display(), e);
                    return PathBuf::from(default_key_name);
                }

                path.push(default_key_name);
                path
            })
            // If the data directory cannot be determined at all, fall back to the current directory.
            .unwrap_or_else(|| PathBuf::from(default_key_name))
    };

    let key_path = cli.key.clone().unwrap_or_else(default_key_path);
    let key = get_or_create_key(&key_path, key_size)?;

    if cli.command.get_path().is_dir() {
        // --- Directory Processing with Progress Bar ---
        let entries: Vec<_> = WalkDir::new(&cli.command.get_path())
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();

        let bar = ProgressBar::new(entries.len() as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )?
                .progress_chars("#>-"),
        );

        println!("Processing {} files...", entries.len());
        entries
            .par_iter()
            .progress_with(bar) // Wrap the iterator with a progress bar
            .for_each(|entry| {
                for _ in 0..cli.repeat {
                    if let Err(e) =
                        process_file(entry.path(), cli.command.clone(), &key, cli.aes256)
                    {
                        // Using eprintln to avoid interfering with progress bar rendering
                        eprintln!("\nFailed to process {}: {}", entry.path().display(), e);
                    }
                }
            });
    } else if cli.command.get_path().is_file() {
        println!("Processing: {}", cli.command.get_path().display());

        for i in 0..cli.repeat {
            // --- Single File Processing with Progress Bar ---
            let file_size = std::fs::metadata(cli.command.get_path())?.len();
            let progress = ProgressBar::new(file_size);
            progress.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("#>-"));
            let source_file = File::open(&cli.command.get_path())?;

            // Wrap the file reader with the progress bar
            let mut reader = progress.wrap_read(source_file);
            let parent_dir = cli
                .command
                .get_path()
                .parent()
                .unwrap_or_else(|| Path::new("."));
            let temp_file = NamedTempFile::new_in(parent_dir)?;
            let mut writer = BufWriter::new(&temp_file);

            if cli.repeat > 1 {
                println!("Repeating {} out of {} times.", i + 1, cli.repeat);
            }

            let result = process_stream(
                cli.command.clone(),
                &mut reader,
                &mut writer,
                &key,
                cli.aes256,
            );

            drop(writer);

            if result.is_ok() {
                temp_file.persist(cli.command.get_path())?;
            } else {
                // The temp file is automatically cleaned up on drop if there's an error.
                return result;
            }
        }
    } else {
        return Err(AppError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "Input path is not a valid file or directory",
        )));
    }

    println!("\nOperation completed successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_key(aes256: bool) -> Vec<u8> {
        let size = if aes256 {
            AES_256_KEY_SIZE
        } else {
            AES_128_KEY_SIZE
        };
        vec![42; size]
    }

    #[test]
    fn test_encrypt_decrypt_stream_aes128() {
        let key = test_key(false);
        let plaintext = b"this is a moderately long test message for streaming encryption.";

        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Cursor::new(Vec::new());

        process_stream(
            Command::Encrypt {
                path: PathBuf::new(),
            },
            &mut source,
            &mut encrypted_dest,
            &key,
            false,
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());

        process_stream(
            Command::Decrypt {
                path: PathBuf::new(),
            },
            &mut encrypted_source,
            &mut decrypted_dest,
            &key,
            false,
        )
        .unwrap();

        assert_eq!(plaintext.to_vec(), decrypted_dest.into_inner());
    }

    #[test]
    fn test_encrypt_decrypt_stream_aes256() {
        let key = test_key(true);
        let plaintext =
            b"this is a moderately long test message for streaming encryption with AES256.";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Cursor::new(Vec::new());

        process_stream(
            Command::Encrypt {
                path: PathBuf::new(),
            },
            &mut source,
            &mut encrypted_dest,
            &key,
            true,
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());

        process_stream(
            Command::Decrypt {
                path: PathBuf::new(),
            },
            &mut encrypted_source,
            &mut decrypted_dest,
            &key,
            true,
        )
        .unwrap();

        assert_eq!(plaintext.to_vec(), decrypted_dest.into_inner());
    }

    #[test]
    fn test_decryption_failure_on_tampered_data() {
        let key = test_key(false);
        let plaintext = b"do not tamper with this data";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Cursor::new(Vec::new());

        process_stream(
            Command::Encrypt {
                path: PathBuf::new(),
            },
            &mut source,
            &mut encrypted_dest,
            &key,
            false,
        )
        .unwrap();
        let mut tampered_data = encrypted_dest.into_inner();

        // Tamper with the last byte of the ciphertext
        let last_byte_index = tampered_data.len() - 1;
        tampered_data[last_byte_index] = tampered_data[last_byte_index].wrapping_add(1);

        let mut tampered_source = Cursor::new(tampered_data);
        let mut decrypted_dest = Cursor::new(Vec::new());

        // Decryption should fail
        let result = process_stream(
            Command::Decrypt {
                path: PathBuf::new(),
            },
            &mut tampered_source,
            &mut decrypted_dest,
            &key,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::Crypto(_)));
    }

    #[test]
    fn test_get_or_create_key_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("test.key");
        let key_size = AES_128_KEY_SIZE;

        // 1. Key doesn't exist, should be created
        let key1 = get_or_create_key(&key_path, key_size).unwrap();
        assert_eq!(key1.len(), key_size);
        assert!(key_path.exists());

        // 2. Key exists, should be read
        let key2 = get_or_create_key(&key_path, key_size).unwrap();
        assert_eq!(key1, key2);

        // 3. Invalid key length
        std::fs::write(&key_path, vec![0; 10]).unwrap();
        let result = get_or_create_key(&key_path, key_size);
        assert!(matches!(
            result.unwrap_err(),
            AppError::InvalidKeyLength {
                expected: 16,
                actual: 10
            }
        ));
    }

    const LARGE_FILE_SIZE: usize = 500 * 1024 * 1024; // 500 MB

    #[test]
    #[ignore] // This test is slow, run with `cargo test -- --ignored`
    fn test_large_file_encrypt_decrypt_aes128() {
        println!("Running 100MB AES-128 stream test (this may take a moment)...");
        let key = test_key(false);
        // Create a large vector of repeating bytes to simulate a large file
        let plaintext = vec![42u8; LARGE_FILE_SIZE];
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Cursor::new(Vec::new());

        // Encrypt
        process_stream(
            Command::Encrypt {
                path: PathBuf::new(),
            },
            &mut source,
            &mut encrypted_dest,
            &key,
            false,
        )
        .unwrap();
        let encrypted_data = encrypted_dest.into_inner();

        // Ensure ciphertext is not the same as plaintext and has nonce + tag overhead
        assert_ne!(plaintext.len(), encrypted_data.len());
        assert_ne!(plaintext, encrypted_data);

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_data);
        let mut decrypted_dest = Cursor::new(Vec::new());
        process_stream(
            Command::Decrypt {
                path: PathBuf::new(),
            },
            &mut encrypted_source,
            &mut decrypted_dest,
            &key,
            false,
        )
        .unwrap();

        // Assert that the decrypted data is identical to the original plaintext
        assert_eq!(plaintext, decrypted_dest.into_inner());
    }

    #[test]
    #[ignore] // This test is slow, run with `cargo test -- --ignored`
    fn test_large_file_encrypt_decrypt_aes256() {
        println!("Running 100MB AES-256 stream test (this may take a moment)...");
        let key = test_key(true);

        // Create a large vector of repeating bytes to simulate a large file
        let plaintext = vec![88u8; LARGE_FILE_SIZE];
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Cursor::new(Vec::new());

        // Encrypt
        process_stream(
            Command::Encrypt {
                path: PathBuf::new(),
            },
            &mut source,
            &mut encrypted_dest,
            &key,
            true,
        )
        .unwrap();
        let encrypted_data = encrypted_dest.into_inner();

        // Ensure ciphertext is not the same as plaintext and has nonce + tag overhead
        assert_ne!(plaintext.len(), encrypted_data.len());
        assert_ne!(plaintext, encrypted_data);

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_data);
        let mut decrypted_dest = Cursor::new(Vec::new());

        process_stream(
            Command::Decrypt {
                path: PathBuf::new(),
            },
            &mut encrypted_source,
            &mut decrypted_dest,
            &key,
            true,
        )
        .unwrap();

        // Assert that the decrypted data is identical to the original plaintext
        assert_eq!(plaintext, decrypted_dest.into_inner());
    }
}
