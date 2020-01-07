use aes::random_block;
use aes::Aes128;
use aes::BLOCK_SIZE;
use aes::MODE;

use std::{error, fmt};

use xor::XOR;

use crate::errors::*;

struct Sender {
    key: Vec<u8>,
}

struct Receiver {
    key: Vec<u8>,
}

impl Sender {
    pub fn get_ciphertext(&self) -> Result<Vec<u8>> {
        let cleartext = b"comment1=cooking%20MCs;userdata=foo@baz.com;comment2=%20like%20a%20pound%20of%20bacon";
        Ok(cleartext.encrypt(&self.key, Some(&self.key), MODE::CBC)?)
    }
}

impl Receiver {
    pub fn try_decrypt(&self, ciphertext: &[u8]) -> Result<()> {
        let cleartext = ciphertext.decrypt(&self.key, Some(&self.key), MODE::CBC)?;
        if !cleartext.is_ascii() {
            Err(NonAscii(cleartext).into())
        } else {
            Ok(())
        }
    }

    pub fn verify_solution(&self, candidate_key: &[u8]) -> Result<()> {
        compare_eq(&self.key[..], candidate_key)
    }
}

fn get_sender_and_receiver_with_shared_key() -> (Sender, Receiver) {
    let secret_key = random_block();
    let sender = Sender {
        key: secret_key.clone(),
    };
    let receiver = Receiver {
        key: secret_key,
    };
    (sender, receiver)
}

#[derive(Debug, Clone)]
struct NonAscii(Vec<u8>);

// This is important for other errors to wrap this one.
impl error::Error for NonAscii {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl fmt::Display for NonAscii {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid input: {:?}", self)
    }
}

pub fn run() -> Result<()> {
    let (sender, receiver) = get_sender_and_receiver_with_shared_key();
    let ciphertext = sender.get_ciphertext()?;

    if ciphertext.len() < 3 * BLOCK_SIZE {
        return Err("ciphertext does not have expected length".into());
    }

    // Let C_1 be the first block of `ciphertext` and let P_1 be the first block of the
    // cleartext behind `ciphertext` (under CBC). Let K be the unknown key. We know that
    // AES-ECB(C_1) = P_1 XOR K, as K was used as the IV.
    // Our attack ciphertext is C_1 || 0 || C_1. With CBC and K as IV, this will decrypt to
    // AES-ECB(C1) XOR K || * || AES-ECB(C1) XOR 0
    // = P_1 || * || P_1 XOR K.
    // We can therefore recover K by XORing the first and the third block of this cleartext.

    let mut attack_ciphertext = Vec::with_capacity(3 * BLOCK_SIZE);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&[0; BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);

    //Push last two blocks to preserve valid padding at the end
    attack_ciphertext.extend_from_slice(&ciphertext[ciphertext.len() - 2 * BLOCK_SIZE..]);

    if let Err(err) = receiver.try_decrypt(&attack_ciphertext) {
        if let Some(&NonAscii(ref cleartext)) = err.downcast_ref::<NonAscii>() {
            return receiver.verify_solution(
                &cleartext[0..BLOCK_SIZE].xor(&cleartext[2 * BLOCK_SIZE..3 * BLOCK_SIZE]),
            );
        }
    }

    Err("attack ciphertext did not deceive the receiver".into())
}
