use std::ascii::AsciiExt;

use rand;
use rand::Rng;

use aes::{Aes128, MODE};
use aes::BLOCK_SIZE;

use serialize::from_base64;

use errors::*;

use set2::random_block;
use set2::decode_profile;

pub trait Oracle {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>>;
    fn verify_suffix(&self, candidate: &[u8]) -> Result<()>;
}

struct Common {
    key: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    mode: MODE,
}

impl Oracle for Common {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>> {
        let key = &self.key;
        let prefix = &self.prefix;
        let suffix = &self.suffix;
        let mode = self.mode;

        let mut cleartext = Vec::with_capacity(prefix.len() + u.len() + suffix.len());
        cleartext.extend_from_slice(prefix);
        cleartext.extend_from_slice(u);
        cleartext.extend_from_slice(suffix);

        // Only setting iv here depending on the mode seems to be difficult because of type
        // and/or lifetime issues with Option<&[u8]>.
        match mode {
            MODE::CBC => cleartext.encrypt(key, Some(&[0; BLOCK_SIZE]), mode),
            _ => cleartext.encrypt(key, None, mode),
        }.map_err(|err| err.into())
    }

    fn verify_suffix(&self, candidate: &[u8]) -> Result<()> {
        compare(&self.suffix[..], candidate)
    }
}

pub struct Oracle11 {
    common: Common,
    already_called: bool,
}

impl Oracle11 {
    pub fn new() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let key = random_block();
        let prefix_len = rng.gen_range(5, 11);
        let prefix: Vec<u8> = rng.gen_iter().take(prefix_len).collect();
        let suffix_len = rng.gen_range(5, 11);
        let suffix: Vec<u8> = rng.gen_iter().take(suffix_len).collect();

        let use_ecb = rng.gen();
        let mode = if use_ecb {
            MODE::ECB
        } else {
            MODE::CBC
        };

        // TODO let iv = random_block();

        Ok(Oracle11 {
            common: Common {
                key: key,
                prefix: prefix,
                suffix: suffix,
                mode: mode,
            },
            already_called: false,
        })
    }

    pub fn encrypt(&mut self, u: &[u8]) -> Result<Vec<u8>> {
        if self.already_called {
            bail!("Method has already been called. Please generate a fresh oracle.");
        }

        self.already_called = true;
        self.common.encrypt(u)
    }

    pub fn verify_solution(&self, uses_ecb: bool) -> Result<()> {
        compare(self.common.mode == MODE::ECB, uses_ecb)
    }
}

pub struct Oracle12 {
    common: Common,
}

impl Oracle for Oracle12 {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>> {
        self.common.encrypt(u)
    }

    fn verify_suffix(&self, candidate: &[u8]) -> Result<()> {
        self.common.verify_suffix(candidate)
    }
}

impl Oracle12 {
    pub fn new() -> Result<Self> {
        let key = random_block();

        let suffix = from_base64(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv\
             d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvb\
             iBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW\
             91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
        )?;

        Ok(Oracle12 {
            common: Common {
                key: key,
                prefix: Vec::new(),
                suffix: suffix,
                mode: MODE::ECB,
            },
        })
    }
}

pub struct Oracle13 {
    common: Common,
}

impl Oracle for Oracle13 {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>> {
        if u.iter().any(|&c| !c.is_ascii() || c == b'&' || c == b'=') {
            panic!("Invalid input.");
        }

        self.common.encrypt(u)
    }

    fn verify_suffix(&self, candidate: &[u8]) -> Result<()> {
        self.common.verify_suffix(candidate)
    }
}

impl Oracle13 {
    pub fn new() -> Result<Self> {
        let key = random_block();

        let prefix = b"email=".to_vec();
        let suffix = b"&uid=10&role=user".to_vec();

        Ok(Oracle13 {
            common: Common {
                key: key,
                prefix: prefix,
                suffix: suffix,
                mode: MODE::ECB,
            },
        })
    }

    pub fn verify_solution(&self, ciphertext: &[u8]) -> Result<()> {
        compare(
            Some(b"admin".as_ref()),
            decode_profile(
                &ciphertext.decrypt(&self.common.key, None, MODE::ECB)?,
                b'&',
            ).remove(b"role".as_ref()),
        )
    }
}

pub struct Oracle14 {
    common: Common,
}

impl Oracle for Oracle14 {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>> {
        self.common.encrypt(u)
    }

    fn verify_suffix(&self, candidate: &[u8]) -> Result<()> {
        self.common.verify_suffix(candidate)
    }
}

impl Oracle14 {
    pub fn new() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let key: Vec<u8> = rng.gen_iter().take(BLOCK_SIZE).collect();
        let prefix_len = rng.gen_range(1, 200);
        let prefix: Vec<u8> = rng.gen_iter().take(prefix_len).collect();

        let suffix = from_base64(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv\
             d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvb\
             iBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW\
             91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
        )?;

        Ok(Oracle14 {
            common: Common {
                key: key,
                prefix: prefix,
                suffix: suffix,
                mode: MODE::ECB,
            },
        })
    }
}

pub struct Oracle16 {
    common: Common,
}

impl Oracle for Oracle16 {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>> {
        if u.iter().any(|&c| !c.is_ascii() || c == b';' || c == b'=') {
            panic!("Invalid input.");
        }

        self.common.encrypt(u)
    }

    fn verify_suffix(&self, candidate: &[u8]) -> Result<()> {
        self.common.verify_suffix(candidate)
    }
}

impl Oracle16 {
    pub fn new() -> Result<Self> {
        let key = random_block();

        let prefix = b"comment1=cooking%20MCs;userdata=".to_vec();
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();

        Ok(Oracle16 {
            common: Common {
                key: key,
                prefix: prefix,
                suffix: suffix,
                mode: MODE::CBC,
            },
        })
    }

    pub fn verify_solution(&self, ciphertext: &[u8]) -> Result<()> {
        // The flipped next to last block will decrypt to arbitrary cleartext. Depending on the
        // precise implementation of decode_profile, this might cause problems, because this
        // cleartext could for example contain `;foo;`, or `foo=bar=baz`. For now we rely on
        // the fact that decode_profile accepts such inputs.

        compare(
            Some(b"true".as_ref()),
            decode_profile(
                &ciphertext.decrypt(&self.common.key, Some(&[0; BLOCK_SIZE]), MODE::CBC)?,
                b';',
            ).remove(b"admin".as_ref()),
        )
    }
}

pub struct Oracle26 {
    common: Common,
}

impl Oracle for Oracle26 {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>> {
        if u.iter().any(|&c| !c.is_ascii() || c == b';' || c == b'=') {
            panic!("Invalid input.");
        }

        self.common.encrypt(u)
    }

    fn verify_suffix(&self, candidate: &[u8]) -> Result<()> {
        self.common.verify_suffix(candidate)
    }
}

impl Oracle26 {
    pub fn new() -> Result<Self> {
        let key = random_block();

        let prefix = b"comment1=cooking%20MCs;userdata=".to_vec();
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();

        Ok(Oracle26 {
            common: Common {
                key: key,
                prefix: prefix,
                suffix: suffix,
                mode: MODE::CTR,
            },
        })
    }

    pub fn verify_solution(&self, ciphertext: &[u8]) -> Result<()> {
        compare(
            Some(b"true".as_ref()),
            decode_profile(
                &ciphertext.decrypt(&self.common.key, None, MODE::CTR)?,
                b';',
            ).remove(b"admin".as_ref()),
        )
    }
}
