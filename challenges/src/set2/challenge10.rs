use std::path::Path;

use aes::BLOCK_SIZE;
use aes::{Aes128, MODE};

use serialize::from_base64_file;

use set1::read_file_to_string;

use errors::*;

pub fn run() -> Result<(), Error> {
    let key = b"YELLOW SUBMARINE";
    let input = from_base64_file(Path::new("data/10.txt"))?;
    let cleartext = input.decrypt(key, Some(&[0; BLOCK_SIZE]), MODE::CBC)?;

    // Read reference cleartext from file, it is too long to store
    // it inline.
    let cleartext_ref = read_file_to_string("data/10.ref.txt")?;

    compare_eq(cleartext_ref.as_bytes(), &cleartext)
}
