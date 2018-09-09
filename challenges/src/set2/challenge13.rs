use aes::Aes128;
use aes::{BLOCK_SIZE, chunks_count};

use errors::*;

use prefix_suffix_oracles::Oracle;
use prefix_suffix_oracles::Oracle13;

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
    let target_last_block = oracle
        .encrypt(&input)?
        .split_off(prefix_chunks_count * BLOCK_SIZE);

    let (chunks, fill_len) = chunks_count(prefix_plus_suffix_length(&oracle)?);
    let mut ciphertext = oracle.encrypt(&vec![0; fill_len + "user".len()])?;
    compare_eq((chunks + 1) * BLOCK_SIZE, ciphertext.len())?;

    ciphertext[chunks * BLOCK_SIZE..].copy_from_slice(&target_last_block[0..BLOCK_SIZE]);

    oracle.verify_solution(&ciphertext)
}
