extern crate openssl;
extern crate rand;
extern crate xor;

use openssl::symm::{decrypt, encrypt};
use rand::Rng;
use xor::XOR;

use std::error;
use std::fmt;

pub const BLOCK_SIZE: usize = 16;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MODE {
    ECB,
    CBC,
    CTR,
}

#[derive(Debug, Clone)]
pub enum AesError {
    InvalidPadding,
    InvalidParameter,
    EncryptionFailed { block: Vec<u8> },
    DecryptionFailed { block: Vec<u8> },
    IvNotAllowed,
    IvRequired,
    InputNotBlockSize,
    InputNotMultipleOfBlockSize,
    IvNotBlockSize,
}

// This is important for other errors to wrap this one.
impl error::Error for AesError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AesError::InvalidPadding => write!(f, "invalid padding"),
            AesError::EncryptionFailed { block } => write!(f, "failed to encrypt block {:?}", block),
            AesError::DecryptionFailed { block } => write!(f, "failed to decrypt block {:?}", block),
            AesError::InvalidParameter => write!(f, "invalid parameter"),
            AesError::IvNotAllowed => write!(f, "iv not supported in requested mode"),
            AesError::IvRequired => write!(f, "iv required in requested mode"),
            AesError::InputNotBlockSize => write!(f, "input length not equal to {}", BLOCK_SIZE),
            AesError::InputNotMultipleOfBlockSize => write!(f, "input length not a multiple of {}", BLOCK_SIZE),
            AesError::IvNotBlockSize => write!(f, "iv length not equal to {}", BLOCK_SIZE),
        }
    }
}

pub fn pad_inplace(u: &mut Vec<u8>, k: u8) -> Result<(), AesError> {
    if !(k >= 2) {
        return Err(AesError::InvalidParameter);
    }

    let p = k - (u.len() % k as usize) as u8;
    for _ in 0..p {
        u.push(p);
    }
    Ok(())
}

pub fn unpad_inplace(u: &mut Vec<u8>, k: u8) -> Result<(), AesError> {
    if !padding_valid(u, k)? {
        return Err(AesError::InvalidPadding.into());
    }

    let len_new = u.len() - u[u.len() - 1] as usize;
    u.truncate(len_new);
    Ok(())
}

fn padding_valid(u: &[u8], k: u8) -> Result<bool, AesError> {
    if !(k >= 2) {
        return Err(AesError::InvalidParameter);
    }

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
    fn encrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, AesError>;
    fn decrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, AesError>;
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

    fn encrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, AesError> {
        match mode {
            MODE::ECB => {
                if !(iv.is_none()){
                    return Err(AesError::IvNotAllowed);
                }
                encrypt_aes128_ecb(&self, key)
            }

            MODE::CBC => {
                if !(iv.is_some()){
                    return Err(AesError::IvRequired);
                }
                encrypt_aes128_cbc(&self, key, iv.unwrap())
            }

            MODE::CTR => {
                if !(iv.is_none()){
                    return Err(AesError::IvNotAllowed);
                }
                aes128_ctr(&self, key)
            }
        }
    }

    fn decrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, AesError> {
        match mode {
            MODE::ECB => {
                if !(iv.is_none()){
                    return Err(AesError::IvNotAllowed);
                }
                decrypt_aes128_ecb(&self, key)
            }

            MODE::CBC => {
                if !(iv.is_some()){
                    return Err(AesError::IvRequired);
                }
                decrypt_aes128_cbc(&self, key, iv.unwrap())
            }

            MODE::CTR => {
                if !(iv.is_none()){
                    return Err(AesError::IvNotAllowed);
                }
                aes128_ctr(&self, key)
            }
        }
    }
}

fn encrypt_aes128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    if !( input.len() == BLOCK_SIZE){
        return Err(AesError::InputNotBlockSize);
    }

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

fn decrypt_aes128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    if !( input.len() == BLOCK_SIZE){
        return Err(AesError::InputNotBlockSize);
    }

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

fn encrypt_aes128_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    let u = input.pad();
    let mut ciphertext = Vec::new();
    for block in u.chunks(BLOCK_SIZE) {
        ciphertext.extend_from_slice(&encrypt_aes128_block(block, key)?);
    }
    Ok(ciphertext)
}

fn decrypt_aes128_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
    if !( input.len() % BLOCK_SIZE == 0){
        return Err(AesError::InputNotMultipleOfBlockSize);
    }

    let mut cleartext = Vec::new();
    for block in input.chunks(BLOCK_SIZE) {
        cleartext.extend_from_slice(&decrypt_aes128_block(block, key)?);
    }
    unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
    Ok(cleartext)
}

fn encrypt_aes128_cbc(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesError> {
    if !( iv.len() == BLOCK_SIZE){
        return Err(AesError::IvNotBlockSize);
    }

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

fn decrypt_aes128_cbc(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, AesError> {
    if !( input.len() % BLOCK_SIZE == 0){
        return Err(AesError::InputNotMultipleOfBlockSize);
    }
    if !( iv.len() == BLOCK_SIZE){
        return Err(AesError::IvNotBlockSize);
    }

    let mut cleartext = Vec::new();
    let mut previous = iv;
    for block in input.chunks(BLOCK_SIZE) {
        cleartext.extend_from_slice(&decrypt_aes128_block(block, key)?.xor(previous));
        previous = block;
    }
    unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
    Ok(cleartext)
}

fn aes128_ctr(input: &[u8], key: &[u8]) -> Result<Vec<u8>, AesError> {
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
