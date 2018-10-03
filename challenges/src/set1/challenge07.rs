use aes::{Aes128, MODE};

use serialize::from_base64_file;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::errors::*;

pub fn read_file_to_string(file_path: &str) -> Result<String, Error> {
    let path = Path::new(file_path);
    let mut file = File::open(&path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

pub fn run() -> Result<(), Error> {
    let key = b"YELLOW SUBMARINE";
    let ciphertext = from_base64_file(Path::new("data/7.txt"))?;
    let cleartext = ciphertext.decrypt(key, None, MODE::ECB)?;

    // Read reference cleartext from a file,
    // it is too long to store it inline.
    let cleartext_ref = read_file_to_string("data/7.ref.txt")?;

    compare_eq(cleartext_ref.as_bytes(), &cleartext)
}
