# rustencrypter-cli

An encryption cli tool for directories and files written purely in Rust.
Uses AES-GCM with 128 or 256 bit encryption.

![Example of the encryption algorithm](assets/test.gif)

## Installation

```bash
git clone https://github.com/Ayuei/rustencrypter.git
cargo install --path rustencrypter
```

## Usage

```bash
./rustencrypter [encrypt/decrypt] <input file> --[k]ey <key file>
```

**Note encryption and decryption will overwrite the source file**
*You can only do a single encrypt or decrypt operation per call*

## Features

- [x] Encrypt a file
- [x] Encrypt all files in a given directory
- [x] Automatic key generation (creates "key" in os-sensible directory)
or requested directory/file
- [x] User can specify specific key file (16 or 32 bit)
- [x] Fresh nonce every encryption
- [x] Encryption/decryption chaining
- [x] Atomic replacement of files
(interrupted encryption/decryption will not destroy the file)

## Neat things

You can chain multiple encryptions and decryptions symmetrically for added security.

```bash
./rustencrypter encrypt file 
./rustencrypter encrypt file
./rustencrypter decrypt file
./rustencrypter decrypt file
```

## TODOs

- [ ] Release compiled binaries for all platforms
- [ ] Add an optional flag for an output file
- [x] Add authentication for tamper detection (HMAC)
- [x] Refactor for speed using callbacks
- [x] Fix some race conditions in the test cases
- [x] Multi-threads or Async for directory encryption/decryption
- [ ] Add python bindings (personal project)

Feel to do any pull requests or let me know about any issues.
