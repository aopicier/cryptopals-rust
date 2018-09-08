use aes::BLOCK_SIZE;
use aes::Aes128;

use xor::XOR;

use helper::ceil_div;

use errors::*;

use prefix_suffix_oracles::{Oracle, Oracle16};

use set2::challenge12::prefix_plus_suffix_length;

pub fn run() -> Result<(), Error> {
    let oracle = Oracle16::new()?;

    let (blocks, padding) = ceil_div(prefix_plus_suffix_length(&oracle)?, BLOCK_SIZE);
    let mut ciphertext = oracle.encrypt(&vec![0; padding])?;
    compare_eq((blocks + 1) * BLOCK_SIZE, ciphertext.len())?;

    let target_last_block = b";admin=true".pad();
    let current_last_block = vec![BLOCK_SIZE as u8; BLOCK_SIZE];
    let attack_bitflip = target_last_block.xor(&current_last_block);

    // Flip the next to last block
    ciphertext[(blocks - 1) * BLOCK_SIZE..blocks * BLOCK_SIZE].xor_inplace(&attack_bitflip);

    oracle.verify_solution(&ciphertext)
}
