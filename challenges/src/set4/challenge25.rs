use std::path::Path;

use aes::Aes128;
use aes::MODE;
use xor::XOR;

use serialize::from_base64_file;

use set2::random_block;

use errors::*;

struct Encrypter25 {
    cleartext: Vec<u8>,
    key: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Encrypter25 {
    pub fn new() -> Result<Self, Error> {
        let cleartext = from_base64_file(Path::new("data/25.txt"))?;
        let key = random_block();
        let ciphertext = cleartext.encrypt(&key, None, MODE::CTR)?;
        Ok(Encrypter25 {
            cleartext,
            key,
            ciphertext,
        })
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn edit(&self, offset: usize, newtext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut cleartext = self.cleartext.clone();
        let end = offset + newtext.len();
        if end > cleartext.len() {
            bail!("input out of bounds")
        }
        cleartext[offset..end].copy_from_slice(newtext);
        cleartext.encrypt(&self.key, None, MODE::CTR)
    }

    pub fn verify_solution(&self, candidate_cleartext: &[u8]) -> Result<(), Error> {
        compare_eq(&self.cleartext[..], candidate_cleartext)
    }
}

pub fn run() -> Result<(), Error> {
    // This exercise is trivial: In CTR mode, if we know the underlying plaintext at some location,
    // we can trivially recover the used keystream by xor'ing the ciphertext with the
    // known plaintext. We simply use the edit function to set the entire cleartext to 0 so that
    // the ciphertext is even equal to the keystream.

    let encrypter = Encrypter25::new()?;
    let ciphertext = encrypter.get_ciphertext();
    let keystream = encrypter.edit(0, &vec![0; ciphertext.len()])?;
    encrypter.verify_solution(&ciphertext.xor(&keystream))
}
