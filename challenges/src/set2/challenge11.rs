use crate::errors::*;
use crate::prefix_suffix_oracles::Oracle;
use crate::prefix_suffix_oracles::Oracle11;
use aes::BLOCK_SIZE;

// We need an upper bound on the number of prefix chunks that the oracle prepends to our input.
// I claim that it is impossible to detect ECB with just a single call to the oracle without this limit.
pub fn uses_ecb(oracle: &dyn Oracle, prefix_chunks_count_limit: usize) -> Result<bool> {
    let input = vec![0; (prefix_chunks_count_limit + 2) * BLOCK_SIZE];
    let ciphertext = oracle.encrypt(&input)?;
    let blocks: Vec<&[u8]> = ciphertext
        .chunks(BLOCK_SIZE)
        .skip(prefix_chunks_count_limit)
        .take(2)
        .collect();
    Ok(blocks[0] == blocks[1])
}

pub fn run() -> Result<()> {
    let oracle = Oracle11::new()?;
    let uses_ecb = uses_ecb(&oracle, 1)?;
    oracle.verify_solution(uses_ecb)
}
