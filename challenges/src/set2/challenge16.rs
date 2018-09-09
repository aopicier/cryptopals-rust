use aes::Aes128;
use aes::{BLOCK_SIZE, chunks_count};

use xor::XOR;

use errors::*;

use prefix_suffix_oracles::{Oracle, Oracle16};

use super::challenge12::prefix_plus_suffix_length;

pub fn run() -> Result<(), Error> {
    let oracle = Oracle16::new()?;

    // The following input is chosen in such a way that the last block of the cleartext
    // in oracle consists entirely of padding bytes.
    let (chunks_count, fill_len) = chunks_count(prefix_plus_suffix_length(&oracle)?);
    let mut ciphertext = oracle.encrypt(&vec![0; fill_len])?;

    // Sanity check
    compare_eq((chunks_count + 1) * BLOCK_SIZE, ciphertext.len())?;

    let target_last_block = b";admin=true".pad();
    let current_last_block = vec![BLOCK_SIZE as u8; BLOCK_SIZE];
    let attack_bitflip = target_last_block.xor(&current_last_block);

    // Flip the next to last block
    ciphertext[(chunks_count - 1) * BLOCK_SIZE..chunks_count * BLOCK_SIZE].xor_inplace(&attack_bitflip);

    oracle.verify_solution(&ciphertext)
}
