use crate::errors::*;
use aes::{unpad_inplace, Aes128, AesError, BLOCK_SIZE, MODE};
use rand::Rng;
use serialize::from_base64;
use xor::XOR;

use aes::random_block;

struct Server {
    key: Vec<u8>,
}

impl Server {
    fn new() -> Self {
        Self {
            key: random_block(),
        }
    }

    fn get_session_token(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let inputs = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];
        let mut rng = rand::thread_rng();
        let input_index = rng.gen_range(0, inputs.len());
        let input = from_base64(inputs[input_index]).unwrap();
        let iv = random_block();
        let ciphertext = input.encrypt(&self.key, Some(&iv), MODE::CBC)?;
        Ok((iv, ciphertext))
    }

    fn is_padding_valid(&self, iv: &[u8], ciphertext: &[u8]) -> Result<bool> {
        if let Err(error) = ciphertext.decrypt(&self.key, Some(iv), MODE::CBC) {
            match error {
                AesError::InvalidPadding => Ok(false),
                _ => Err(error.into()),
            }
        } else {
            Ok(true)
        }
    }

    fn verify_solution(&self, cleartext: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<()> {
        compare_eq(
            &ciphertext.decrypt(&self.key, Some(iv), MODE::CBC)?[..],
            cleartext,
        )
    }
}

pub fn run() -> Result<()> {
    let server = Server::new();
    let (iv, ciphertext) = server.get_session_token()?;
    let mut cleartext = vec![0; ciphertext.len()];
    let mut prev = iv.clone();
    for (block_index, block) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
        let block_offset = block_index * BLOCK_SIZE;
        for i in (0..BLOCK_SIZE).rev() {
            let padding = (BLOCK_SIZE - i) as u8;
            prev[i + 1..].xor_inplace(&[(padding - 1) ^ padding]);
            for u in 0u8..=255 {
                prev[i] ^= u;
                if server.is_padding_valid(&prev, block)?
                    && (i < BLOCK_SIZE - 1 || {
                        // The last byte of the block requires a special treatment because the padding could
                        // accidentally be valid if we have for example flipped the last byte to the value 2
                        // and the second to last byte of the cleartext also happens to be a 2. We therefore
                        // change the second to last byte and test the padding again. If it is still
                        // valid, we can be sure that the last byte has been flipped to the value 1.
                        prev[i - 1] ^= 1;
                        let result = server.is_padding_valid(&prev, block)?;
                        prev[i - 1] ^= 1;
                        result
                    })
                {
                    cleartext[block_offset + i] = padding ^ u;
                    break;
                }
                prev[i] ^= u;
            }
        }
        prev = block.to_vec();
    }
    unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
    server.verify_solution(&cleartext, &iv, &ciphertext)
}
