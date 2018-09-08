use aes::BLOCK_SIZE;
use errors::*;
use prefix_suffix_oracles::Oracle11;

fn uses_ecb(oracle: &mut Oracle11) -> Result<bool, Error> {
    // Assumes that oracle prepends at most one block of jibber
    let input = vec![0; 3 * BLOCK_SIZE];
    let ciphertext = oracle.encrypt(&input)?;
    let blocks: Vec<&[u8]> = ciphertext.chunks(BLOCK_SIZE).skip(1).take(2).collect();
    Ok(blocks[0] == blocks[1])
}

pub fn run() -> Result<(), Error> {
    let mut oracle = Oracle11::new()?;
    let uses_ecb = uses_ecb(&mut oracle)?;
    oracle.verify_solution(uses_ecb)
}
