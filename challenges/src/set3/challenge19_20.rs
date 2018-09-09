use errors::*;
use set1::break_multibyte_xor_for_keysize;
use aes::random_block;
use std::path::PathBuf;

use aes::{Aes128, MODE};
use serialize::from_base64_lines;

pub enum Exercise {
    _19,
    _20,
}

struct Encrypter {
    key: Vec<u8>,
    exercise: Exercise,
}

impl Encrypter {
    pub fn new(exercise: Exercise) -> Self {
        Encrypter {
            key: random_block(),
            exercise,
        }
    }

    pub fn get_ciphertexts(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut input_file_path = PathBuf::from("data");
        let input_file_name = match self.exercise {
            Exercise::_19 => "19.txt",
            Exercise::_20 => "20.txt",
        };
        input_file_path.push(input_file_name);
        let cleartexts = from_base64_lines(input_file_path.as_path())?;
        cleartexts
            .iter()
            .map(|c| c.encrypt(&self.key, None, MODE::CTR))
            .collect::<Result<Vec<Vec<u8>>, Error>>()
    }

    pub fn verify_solution(&self, candidate_key: &[u8], size: usize) -> Result<(), Error> {
        // TODO: The first entry of the recovered key is wrong because the distribution of first letters
        // of sentences is very different from the overall distribution of letters in a text.
        compare_eq(
            &vec![0; size].encrypt(&self.key, None, MODE::CTR)?[1..],
            &candidate_key[1..],
        )
    }
}

pub fn run(exercise: Exercise) -> Result<(), Error> {
    let encrypter = Encrypter::new(exercise);
    let ciphertexts = encrypter.get_ciphertexts()?;
    let size = ciphertexts.iter().map(|c| c.len()).min().unwrap(); // unwrap is ok
    let ciphertext: Vec<u8> = ciphertexts.iter().flat_map(|ciphertext| &ciphertext[..size]).map(|&u| u).collect();
    let key = break_multibyte_xor_for_keysize(&ciphertext, size);
    encrypter.verify_solution(&key, size)
}
