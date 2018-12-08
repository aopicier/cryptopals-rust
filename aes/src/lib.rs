#[macro_use]
extern crate failure;
extern crate openssl;
extern crate rand;
extern crate xor;

use openssl::symm::{decrypt, encrypt};
use rand::Rng;
use xor::XOR;

pub const BLOCK_SIZE: usize = 16;

use failure::Error;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MODE {
    ECB,
    CBC,
    CTR,
}

#[derive(Debug, Fail)]
pub enum AesError {
    #[fail(display = "invalid padding")]
    InvalidPadding,

    #[fail(display = "failed to encrypt block {:?}", block)]
    EncryptionFailed { block: Vec<u8> },

    #[fail(display = "failed to decrypt block {:?}", block)]
    DecryptionFailed { block: Vec<u8> },
}

pub fn pad_inplace(u: &mut Vec<u8>, k: u8) -> Result<(), Error> {
    ensure!(k >= 2, "invalid parameter");

    let p = k - (u.len() % k as usize) as u8;
    for _ in 0..p {
        u.push(p);
    }
    Ok(())
}

pub fn unpad_inplace(u: &mut Vec<u8>, k: u8) -> Result<(), Error> {
    if !padding_valid(u, k)? {
        return Err(AesError::InvalidPadding.into());
    }

    let len_new = u.len() - u[u.len() - 1] as usize;
    u.truncate(len_new);
    Ok(())
}

fn padding_valid(u: &[u8], k: u8) -> Result<bool, Error> {
    ensure!(k >= 2, "invalid parameter");

    if u.is_empty() || u.len() % k as usize != 0 {
        return Ok(false);
    }

    let padding = u[u.len() - 1];
    if !(1 <= padding && padding <= k) {
        return Ok(false);
    }

    Ok(u[u.len() - padding as usize..]
        .iter()
        .all(|&b| b == padding))
}

pub trait Aes128 {
    fn pad(&self) -> Vec<u8>;
    fn padding_valid(&self) -> bool;
    fn encrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error>;
}

impl Aes128 for [u8] {
    fn pad(&self) -> Vec<u8> {
        let mut v = self.to_vec();
        pad_inplace(&mut v, BLOCK_SIZE as u8).unwrap(); // unwrap is ok
        v
    }

    fn padding_valid(&self) -> bool {
        padding_valid(self, BLOCK_SIZE as u8).unwrap()
    }

    fn encrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error> {
        match mode {
            MODE::ECB => {
                ensure!(iv.is_none(), "iv not supported for ECB mode");
                encrypt_aes128_ecb(&self, key)
            }

            MODE::CBC => {
                ensure!(iv.is_some(), "iv required for CBC mode");
                encrypt_aes128_cbc(&self, key, iv.unwrap())
            }

            MODE::CTR => {
                ensure!(iv.is_none(), "iv not supported for CTR mode");
                aes128_ctr(&self, key)
            }
        }
    }

    fn decrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error> {
        match mode {
            MODE::ECB => {
                ensure!(iv.is_none(), "iv not supported for ECB mode");
                decrypt_aes128_ecb(&self, key)
            }

            MODE::CBC => {
                ensure!(iv.is_some(), "iv required for CBC mode");
                decrypt_aes128_cbc(&self, key, iv.unwrap())
            }

            MODE::CTR => {
                ensure!(iv.is_none(), "iv not supported for CTR mode");
                aes128_ctr(&self, key)
            }
        }
    }
}

fn encrypt_aes128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    ensure!(
        input.len() == BLOCK_SIZE,
        format!("input does not consist of {} bytes", BLOCK_SIZE)
    );

    // The OpenSSL call pads the cleartext before encrypting.
    let mut ciphertext =
        encrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, input).map_err(|_| {
            AesError::EncryptionFailed {
                block: input.to_vec(),
            }
        })?;

    ciphertext.truncate(BLOCK_SIZE);
    Ok(ciphertext)
}

fn decrypt_aes128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    ensure!(
        input.len() == BLOCK_SIZE,
        format!("input does not consist of {} bytes", BLOCK_SIZE)
    );

    // The OpenSSL call expects a padded cleartext.
    let padding = encrypt_aes128_block(&[BLOCK_SIZE as u8; BLOCK_SIZE], key)?;
    let mut u = input.to_vec();
    u.extend_from_slice(&padding);
    decrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, &u).map_err(|_| {
        AesError::DecryptionFailed {
            block: input.to_vec(),
        }
        .into()
    })
}

fn encrypt_aes128_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let u = input.pad();
    let mut ciphertext = Vec::new();
    for block in u.chunks(BLOCK_SIZE) {
        ciphertext.extend_from_slice(&encrypt_aes128_block(block, key)?);
    }
    Ok(ciphertext)
}

fn decrypt_aes128_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    ensure!(
        input.len() % BLOCK_SIZE == 0,
        format!("input length not a multiple of {}", BLOCK_SIZE)
    );

    let mut cleartext = Vec::new();
    for block in input.chunks(BLOCK_SIZE) {
        cleartext.extend_from_slice(&decrypt_aes128_block(block, key)?);
    }
    unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
    Ok(cleartext)
}

fn encrypt_aes128_cbc(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    ensure!(
        iv.len() == BLOCK_SIZE,
        format!("iv length not equal to {}", BLOCK_SIZE)
    );

    let u = input.pad();
    let mut ciphertext = Vec::new();
    let mut previous = iv.to_vec();
    for block in u.chunks(BLOCK_SIZE) {
        let current = encrypt_aes128_block(&block.xor(&previous), key)?;
        ciphertext.extend_from_slice(&current);
        previous = current;
    }
    Ok(ciphertext)
}

fn decrypt_aes128_cbc(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    ensure!(
        input.len() % BLOCK_SIZE == 0,
        format!("input length not a multiple of {}", BLOCK_SIZE)
    );
    ensure!(
        iv.len() == BLOCK_SIZE,
        format!("iv length not equal to {}", BLOCK_SIZE)
    );

    let mut cleartext = Vec::new();
    let mut previous = iv;
    for block in input.chunks(BLOCK_SIZE) {
        cleartext.extend_from_slice(&decrypt_aes128_block(block, key)?.xor(previous));
        previous = block;
    }
    unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
    Ok(cleartext)
}

fn aes128_ctr(input: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut ciphertext = Vec::new();
    let mut keystream = vec![0; BLOCK_SIZE];
    for b in input.chunks(BLOCK_SIZE) {
        ciphertext.extend_from_slice(&b.xor(&encrypt_aes128_ecb(&keystream, key)?));
        increment_counter(&mut keystream[BLOCK_SIZE / 2..]);
    }
    Ok(ciphertext)
}

fn increment_counter(v: &mut [u8]) {
    for b in v.iter_mut() {
        *b += 1;
        if *b != 0 {
            break;
        }
    }
}

pub fn random_block() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    rng.gen_iter().take(BLOCK_SIZE).collect()
}

// Returns a pair (chunks_count, fill_len), where chunks_count is the number of
// chunks resulting from dividing a message of length len into chunks of size
// BLOCK_SIZE. This count explicitly includes the last chunk, which may
// be shorter than BLOCK_SIZE. The number fill_len is the difference between
// chunks_count * BLOCK_SIZE and len.
pub fn chunks_count(len: usize) -> (usize, usize) {
    let q = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    let r = q * BLOCK_SIZE - len;
    (q, r)
}

#[test]
fn aes_128_cbc() {
    let iv = [0; BLOCK_SIZE];
    let key = b"YELLOW SUBMARINE";
    let input = b"ABCDEFGHIJKLMNOP";
    assert_eq!(
        input.as_ref(),
        &input
            .encrypt(key, Some(&iv), MODE::CBC)
            .unwrap()
            .decrypt(key, Some(&iv), MODE::CBC)
            .unwrap()[..]
    );
}

#[test]
fn test_padding_valid() {
    assert!(padding_valid("ICE ICE BABY\x04\x04\x04\x04".as_bytes(), 16).unwrap() == true);
    assert!(padding_valid("ICE ICE BABY\x05\x05\x05\x05".as_bytes(), 16).unwrap() == false);
    assert!(padding_valid("ICE ICE BABY\x03\x03\x03".as_bytes(), 16).unwrap() == false);
    assert!(padding_valid("ICE ICE BABY\x01\x02\x03\x04".as_bytes(), 16).unwrap() == false);
    assert!(
        padding_valid(
            "ICE ICE BABY\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C".as_bytes(),
            12
        )
        .unwrap()
            == true
    );
}
