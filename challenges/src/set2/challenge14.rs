use errors::*;

use aes::BLOCK_SIZE;

use prefix_suffix_oracles::Oracle14;

use super::challenge11::uses_ecb;
use super::challenge12::{block_size, decrypt_suffix};

pub fn run() -> Result<(), Error> {
    let oracle = Oracle14::new()?;
    ensure!(
        block_size(&oracle)? == BLOCK_SIZE,
        "oracle does not use expected block size"
    );

    ensure!(uses_ecb(&oracle, 200)?, "oracle does not use ECB");
    oracle.verify_suffix(&decrypt_suffix(&oracle)?)
}
