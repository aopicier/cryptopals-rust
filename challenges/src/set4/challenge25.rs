use std::path::Path;

use aes::Aes128;
use aes::MODE;
use xor::XOR;

use serialize::from_base64_file;

use aes::random_block;

use crate::errors::*;

struct Encrypter {
    cleartext: Vec<u8>,
    key: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Encrypter {
    pub fn new() -> Result<Self> {
        let cleartext = from_base64_file(Path::new("data/25.txt"))?;
        let key = random_block();
        let ciphertext = cleartext.encrypt(&key, None, MODE::CTR)?;
        Ok(Encrypter {
            cleartext,
            key,
            ciphertext,
        })
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn edit(&self, offset: usize, newtext: &[u8]) -> Result<Vec<u8>> {
        let mut cleartext = self.cleartext.clone();
        let end = offset + newtext.len();
        if end > cleartext.len() {
            return Err("input out of bounds".into())
        }
        cleartext[offset..end].copy_from_slice(newtext);
        Ok(cleartext.encrypt(&self.key, None, MODE::CTR)?)
    }

    pub fn verify_solution(&self, candidate_cleartext: &[u8]) -> Result<()> {
        compare_eq(&self.cleartext[..], candidate_cleartext)
    }
}

pub fn run() -> Result<()> {
    // This exercise is trivial: In CTR mode, if we know the underlying plaintext at some location,
    // we can trivially recover the used keystream by xor'ing the ciphertext with the
    // known plaintext. We simply use the edit function to set the entire cleartext to 0 so that
    // the ciphertext is even equal to the keystream.

    let encrypter = Encrypter::new()?;
    let ciphertext = encrypter.get_ciphertext();
    let keystream = encrypter.edit(0, &vec![0; ciphertext.len()])?;
    encrypter.verify_solution(&ciphertext.xor(&keystream))
}
