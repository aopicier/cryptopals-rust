use aes::Aes128;
use aes::BLOCK_SIZE;
use aes::MODE;

use xor::XOR;

use aes::random_block;

use errors::*;

struct Sender {
    key: Vec<u8>,
}

struct Receiver {
    key: Vec<u8>,
}

impl Sender {
    pub fn get_ciphertext(&self) -> Result<Vec<u8>, Error> {
        let cleartext = b"comment1=cooking%20MCs;userdata=foo@baz.com;comment2=%20like%20a%20pound%20of%20bacon";
        cleartext.encrypt(&self.key, Some(&self.key), MODE::CBC)
    }
}

impl Receiver {
    pub fn try_decrypt(&self, ciphertext: &[u8]) -> Result<(), Error> {
        let cleartext = ciphertext.decrypt(&self.key, Some(&self.key), MODE::CBC)?;
        if !cleartext.is_ascii() {
            Err(NonAscii(cleartext).into())
        } else {
            Ok(())
        }
    }

    pub fn verify_solution(&self, candidate_key: &[u8]) -> Result<(), Error> {
        compare_eq(&self.key[..], candidate_key)
    }
}

fn get_sender_and_receiver_with_shared_key() -> (Sender, Receiver) {
    let secret_key = random_block();
    let sender = Sender {
        key: secret_key.clone(),
    };
    let receiver = Receiver {
        key: secret_key.clone(),
    };
    (sender, receiver)
}

#[derive(Debug, Fail)]
#[fail(display = "invalid input: {:?}", _0)]
struct NonAscii(Vec<u8>);

pub fn run() -> Result<(), Error> {
    let (sender, receiver) = get_sender_and_receiver_with_shared_key();
    let ciphertext = sender.get_ciphertext()?;

    ensure!(ciphertext.len() >= 3*BLOCK_SIZE, "ciphertext does not have expected length");

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
        if let Ok(NonAscii(cleartext)) = err.downcast::<NonAscii>() {
            return receiver.verify_solution(
                &cleartext[0..BLOCK_SIZE]
                    .xor(&cleartext[2 * BLOCK_SIZE..3 * BLOCK_SIZE]),
            );
        }
    }

    bail!("attack ciphertext did not deceive the receiver");
}
