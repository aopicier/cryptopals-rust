use crate::errors::*;

use aes::BLOCK_SIZE;

use crate::prefix_suffix_oracles::Oracle14;

use super::challenge11::uses_ecb;
use super::challenge12::{block_size, decrypt_suffix};

pub fn run() -> Result<()> {
    let oracle = Oracle14::new()?;
    if !(block_size(&oracle)? == BLOCK_SIZE) {
        return Err("oracle does not use expected block size".into());
    }

    if !(uses_ecb(&oracle, 200)?) {
        return Err("oracle does not use ECB".into());
    }
    oracle.verify_suffix(&decrypt_suffix(&oracle)?)
}
