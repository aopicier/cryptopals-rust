use aes::Aes128;
use aes::BLOCK_SIZE;
use aes::MODE;

use xor::XOR;

use aes::random_block;

use errors::*;

struct Sender27 {
    key: Vec<u8>,
}

struct Receiver27 {
    key: Vec<u8>,
}

impl Sender27 {
    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        // Exclude ';' and '='
        if input
            .iter()
            .any(|&c| !c.is_ascii() || c == b';' || c == b'=')
        {
            bail!("invalid character in input");
        }

        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        let mut cleartext = Vec::with_capacity(prefix.len() + input.len() + suffix.len());
        cleartext.extend_from_slice(prefix);
        cleartext.extend_from_slice(input);
        cleartext.extend_from_slice(suffix);
        cleartext.encrypt(&self.key, Some(&self.key), MODE::CBC)
    }
}

impl Receiver27 {
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

fn get_sender_and_receiver_with_shared_key() -> (Sender27, Receiver27) {
    let secret_key = random_block();
    let sender = Sender27 {
        key: secret_key.clone(),
    };
    let receiver = Receiver27 {
        key: secret_key.clone(),
    };
    (sender, receiver)
}

#[derive(Debug, Fail)]
#[fail(display = "invalid input: {:?}", _0)]
struct NonAscii(Vec<u8>);

pub fn run() -> Result<(), Error> {
    let (sender, receiver) = get_sender_and_receiver_with_shared_key();

    let ciphertext = sender.encrypt(&[])?;

    let mut attack_ciphertext = Vec::with_capacity(3 * BLOCK_SIZE);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&[0; BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);
    //Push last two blocks to preserve valid padding at the end
    attack_ciphertext.extend_from_slice(&ciphertext[ciphertext.len() - 2 * BLOCK_SIZE..]);

    if let Err(err) = receiver.try_decrypt(&attack_ciphertext) {
        if let Ok(NonAscii(attack_cleartext)) = err.downcast::<NonAscii>() {
            return receiver.verify_solution(
                &attack_cleartext[0..BLOCK_SIZE]
                    .xor(&attack_cleartext[2 * BLOCK_SIZE..3 * BLOCK_SIZE]),
            );
        }
    }

    bail!("attack ciphertext did not deceive the receiver");
}
