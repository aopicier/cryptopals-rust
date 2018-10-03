use aes::Aes128;
use aes::{chunks_count, BLOCK_SIZE};

use crate::errors::*;

use crate::prefix_suffix_oracles::Oracle;
use crate::prefix_suffix_oracles::Oracle13;

use super::challenge12::prefix_plus_suffix_length;
use super::prefix_length;

// The following function works under the single assumption that the target value "user" (to be
// replaced by "admin") is stored at the very end of the profile.

pub fn run() -> Result<(), Error> {
    let oracle = Oracle13::new()?;

    let prefix_len = prefix_length(&oracle)?;
    let (prefix_chunks_count, prefix_fill_len) = chunks_count(prefix_len);
    let target_cleartext = b"admin".pad();
    let mut input = vec![0; prefix_fill_len];
    input.extend_from_slice(&target_cleartext);

    // Determine the ciphertext for target_cleartext
    let target_last_block = &oracle
        .encrypt(&input)?
        .split_off(prefix_chunks_count * BLOCK_SIZE)[0..BLOCK_SIZE];

    // The following input is chosen in such a way that the cleartext in oracle looks as follows:
    // email=\0 ... \0 || \0 ...\0&uid=10&role= || user <- padding ->
    let (chunks_count, fill_len) = chunks_count(prefix_plus_suffix_length(&oracle)?);
    let mut ciphertext = oracle.encrypt(&vec![0; fill_len + "user".len()])?;

    // Sanity check
    compare_eq((chunks_count + 1) * BLOCK_SIZE, ciphertext.len())?;

    // Replace last block with target_last_block
    ciphertext[chunks_count * BLOCK_SIZE..].copy_from_slice(target_last_block);

    oracle.verify_solution(&ciphertext)
}
