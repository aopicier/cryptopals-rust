use aes::Aes128;
use aes::BLOCK_SIZE;

use helper::ceil_div;

use errors::*;

use prefix_suffix_oracles::Oracle;
use prefix_suffix_oracles::Oracle13;

use set2::challenge12::prefix_plus_suffix_length;
use set2::prefix_length;

pub fn run() -> Result<(), Error> {
    let oracle = Oracle13::new()?;

    let prefix_len = prefix_length(&oracle)?;
    let (prefix_blocks, prefix_padding) = ceil_div(prefix_len, BLOCK_SIZE);
    let target_cleartext = b"admin".pad();
    let mut input = vec![0; prefix_padding];
    input.extend_from_slice(&target_cleartext);
    let target_last_block = oracle
        .encrypt(&input)?
        .split_off(prefix_blocks * BLOCK_SIZE);

    let (blocks, padding) = ceil_div(prefix_plus_suffix_length(&oracle)?, BLOCK_SIZE);
    let mut ciphertext = oracle.encrypt(&vec![0; padding + "user".len()])?;
    compare_eq((blocks + 1) * BLOCK_SIZE, ciphertext.len())?;

    ciphertext[blocks * BLOCK_SIZE..].copy_from_slice(&target_last_block[0..BLOCK_SIZE]);

    oracle.verify_solution(&ciphertext)
}
