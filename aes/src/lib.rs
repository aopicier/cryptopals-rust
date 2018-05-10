#[macro_use]
extern crate failure;
extern crate openssl;
extern crate xor;

use openssl::symm::{decrypt, encrypt};
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
    EncryptionFailed {
        block: Vec<u8>
    },

    #[fail(display = "failed to decrypt block {:?}", block)]
    DecryptionFailed {
        block: Vec<u8>
    }
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

pub fn pad(u: &[u8], k: u8) -> Result<Vec<u8>, Error> {
    let mut v = u.to_vec();
    pad_inplace(&mut v, k)?;
    Ok(v)
}

pub fn padding_valid(u: &[u8], k: u8) -> Result<bool, Error> {
    ensure!(k >= 2, "invalid parameter");

    if u.is_empty() || u.len() % k as usize != 0 {
        return Ok(false);
    }
    let padding = u[u.len() - 1];
    if !(1 <= padding && padding <= k) {
        return Ok(false);
    }
    Ok(
        u[u.len() - padding as usize..]
            .iter()
            .all(|&b| b == padding),
    )
}

trait Crypto {
    //fn pad(&self, k: u8) -> Result<Vec<u8>, Error>;
    //fn padding_valid(&self, k: u8) -> Result<bool, Error>;
    fn encrypt_aes128_block(&self, key: &Self) -> Result<Vec<u8>, Error>;
    fn decrypt_aes128_block(&self, key: &Self) -> Result<Vec<u8>, Error>;
    fn encrypt_aes128_ecb(&self, key: &Self) -> Result<Vec<u8>, Error>;
    fn decrypt_aes128_ecb(&self, key: &Self) -> Result<Vec<u8>, Error>;
    fn encrypt_aes128_cbc(&self, key: &Self, iv: &Self) -> Result<Vec<u8>, Error>;
    fn decrypt_aes128_cbc(&self, key: &Self, iv: &Self) -> Result<Vec<u8>, Error>;
    fn decrypt_aes128_cbc_blocks(&self, key: &Self, iv: &Self) -> Result<Vec<u8>, Error>;
    fn aes128_ctr(&self, key: &Self) -> Result<Vec<u8>, Error>;
}

pub trait Aes128 {
    fn pad(&self) -> Vec<u8>;
    fn padding_valid(&self) -> bool;
    fn encrypt_block(&self, key: &Self) -> Result<Vec<u8>, Error>;
    fn decrypt_block(&self, key: &Self) -> Result<Vec<u8>, Error>;
    fn encrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error>;
    fn decrypt_cbc_blocks(&self, key: &Self, iv: &Self) -> Result<Vec<u8>, Error>;
}

impl Aes128 for [u8] {
    fn pad(&self) -> Vec<u8> {
        pad(self, BLOCK_SIZE as u8).unwrap()
    }

    fn padding_valid(&self) -> bool {
        padding_valid(self, BLOCK_SIZE as u8).unwrap()
    }

    fn encrypt_block(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        ensure!(
            self.len() == BLOCK_SIZE,
            format!("input does not consist of {} bytes", BLOCK_SIZE)
        );

        let mut ciphertext = encrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, self)
            .map_err(|_| AesError::EncryptionFailed { block:  self.to_vec() })?;

        ciphertext.truncate(BLOCK_SIZE);
        Ok(ciphertext)
    }

    fn decrypt_block(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        ensure!(
            self.len() == BLOCK_SIZE,
            format!("input does not consist of {} bytes", BLOCK_SIZE)
        );

        let dummy_padding = vec![BLOCK_SIZE as u8; BLOCK_SIZE].encrypt_aes128_block(key)?;
        let mut u = self.to_vec();
        u.extend_from_slice(&dummy_padding);
        decrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, &u)
            .map_err(|_| AesError::DecryptionFailed { block:  self.to_vec() }.into())
    }

    fn encrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error> {
        match mode {
            MODE::ECB => {
                ensure!(iv.is_none(), "iv not supported for ECB mode");
                self.encrypt_aes128_ecb(key)
            }

            MODE::CBC => {
                ensure!(iv.is_some(), "iv required for CBC mode");
                self.encrypt_aes128_cbc(key, iv.unwrap())
            }

            MODE::CTR => {
                ensure!(iv.is_none(), "iv not supported for CTR mode");
                self.aes128_ctr(key)
            }
        }
    }

    fn decrypt(&self, key: &Self, iv: Option<&Self>, mode: MODE) -> Result<Vec<u8>, Error> {
        match mode {
            MODE::ECB => {
                ensure!(iv.is_none(), "iv not supported for ECB mode");
                self.decrypt_aes128_ecb(key)
            }

            MODE::CBC => {
                ensure!(iv.is_some(), "iv required for CBC mode");
                self.decrypt_aes128_cbc(key, iv.unwrap())
            }

            MODE::CTR => {
                ensure!(iv.is_none(), "iv not supported for CTR mode");
                self.aes128_ctr(key)
            }
        }
    }

    fn decrypt_cbc_blocks(&self, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        ensure!(
            self.len() % BLOCK_SIZE == 0,
            format!("input length not a multiple of {}", BLOCK_SIZE)
        );

        let mut cleartext = Vec::new();
        let mut prev = iv;
        for block in self.chunks(BLOCK_SIZE) {
            let cur = block.decrypt_aes128_block(key)?.xor(prev);
            cleartext.extend_from_slice(&cur);
            prev = block;
        }
        Ok(cleartext)
    }
}

#[test]
fn test_padding_valid() {
    //assert!("ICE ICE BABY\x04\x04\x04\x04".as_bytes().padding_valid(16) == true);
    //assert!("ICE ICE BABY\x05\x05\x05\x05".as_bytes().padding_valid(16) == false);
    //assert!("ICE ICE BABY\x03\x03\x03".as_bytes().padding_valid(16) == false);
    //assert!("ICE ICE BABY\x01\x02\x03\x04".as_bytes().padding_valid(16) == false);
    //assert!("ICE ICE BABY\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C".as_bytes().padding_valid(12) == true);

}

impl Crypto for [u8] {
    /*
    fn pad(&self, k: u8) -> Result<Vec<u8>, Error> {
        let mut u = self.to_vec();
        pad_inplace(&mut u, k)?;
        Ok(u)
    }

    fn padding_valid(&self, k: u8) -> Result<bool, Error> {
        if k <= 1 { bail!("invalid parameter"); }
        if self.is_empty() || self.len() % k as usize != 0 {
            return Ok(false);
        }
        let padding = self[self.len() - 1];
        if !(1 <= padding && padding <= k) {
            return Ok(false);
        }
        Ok(self[self.len() - padding as usize..].iter().all(|&u| u == padding))
    }
    */

    fn encrypt_aes128_block(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        if self.len() != BLOCK_SIZE {
            bail!(format!("input does not consist of {} bytes", BLOCK_SIZE));
        }

        let mut ciphertext = encrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, self)
            .map_err(|_| AesError::EncryptionFailed { block:  self.to_vec() })?;

        ciphertext.truncate(BLOCK_SIZE);
        Ok(ciphertext)
    }

    fn decrypt_aes128_block(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        if self.len() != BLOCK_SIZE {
            bail!(format!("input does not consist of {} bytes", BLOCK_SIZE));
        }

        let dummy_padding = vec![BLOCK_SIZE as u8; BLOCK_SIZE].encrypt_aes128_block(key)?;
        let mut u = self.to_vec();
        u.extend_from_slice(&dummy_padding);
        decrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, &u)
            .map_err(|_| AesError::DecryptionFailed { block:  self.to_vec() }.into())
    }

    fn encrypt_aes128_ecb(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        let u = self.pad();
        let mut ciphertext = Vec::new();
        for block in u.chunks(BLOCK_SIZE) {
            ciphertext.extend_from_slice(&block.encrypt_aes128_block(key)?);
        }
        Ok(ciphertext)
    }

    fn decrypt_aes128_ecb(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        if self.len() % BLOCK_SIZE != 0 {
            bail!(format!("input length not a multiple of {}", BLOCK_SIZE));
        }

        let mut cleartext = Vec::new();
        for block in self.chunks(BLOCK_SIZE) {
            cleartext.extend_from_slice(&block.decrypt_aes128_block(key)?);
        }
        unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
        Ok(cleartext)
    }

    fn encrypt_aes128_cbc(&self, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        let u = self.pad();
        let mut ciphertext = Vec::new();
        let mut cur = iv.to_vec();
        for block in u.chunks(BLOCK_SIZE) {
            cur = block.xor(&cur).encrypt_aes128_block(key)?;
            ciphertext.extend_from_slice(&cur);
        }
        Ok(ciphertext)
    }

    fn decrypt_aes128_cbc_blocks(&self, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        if self.len() % BLOCK_SIZE != 0 {
            bail!(format!("input length not a multiple of {}", BLOCK_SIZE));
        }

        let mut cleartext = Vec::new();
        let mut prev = iv;
        for block in self.chunks(BLOCK_SIZE) {
            let cur = block.decrypt_aes128_block(key)?.xor(prev);
            cleartext.extend_from_slice(&cur);
            prev = block;
        }
        Ok(cleartext)
    }

    fn decrypt_aes128_cbc(&self, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        let mut cleartext = self.decrypt_aes128_cbc_blocks(key, iv)?;
        unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
        Ok(cleartext)
    }

    fn aes128_ctr(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ciphertext = Vec::new();
        let mut keystream = vec![0; BLOCK_SIZE];
        for b in self.chunks(BLOCK_SIZE) {
            ciphertext.extend_from_slice(&b.xor(&keystream.encrypt_aes128_ecb(key)?));
            increment_counter(&mut keystream[BLOCK_SIZE / 2..]);
        }
        Ok(ciphertext)
    }
}

pub fn increment_counter(v: &mut [u8]) {
    for b in v.iter_mut() {
        *b += 1;
        if *b != 0 {
            break;
        }
    }
}
