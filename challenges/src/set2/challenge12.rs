use aes::BLOCK_SIZE;
use errors::*;
use helper::ceil_quotient;
use std;

use prefix_suffix_oracles::Oracle12;
use prefix_suffix_oracles::{DeterministicOracle, Oracle};

fn uses_padding<T: Oracle>(oracle: &T) -> Result<bool, Error> {
    Ok((oracle.encrypt(&[0])?.len() - oracle.encrypt(&[])?.len()) % BLOCK_SIZE == 0)
}

pub fn prefix_plus_suffix_length<T: Oracle>(oracle: &T) -> Result<usize, Error> {
    let initial = oracle.encrypt(&[])?.len();
    if !uses_padding(oracle)? {
        return Ok(initial);
    }

    let input = [0; BLOCK_SIZE];
    if let Some(index) = (1..=BLOCK_SIZE).find(|&i| {
        if let Ok(ciphertext) = oracle.encrypt(&input[..i]) {
            initial != ciphertext.len()
        } else {
            false
        }
    }) {
        Ok(initial - index)
    } else {
        bail!(
            "length of oracle output did not change, something is wrong with the provided oracle"
        );
    }
}

// For an oracle prepending prefix and appending suffix to its input, this function returns
// prefix.len()/BLOCK_SIZE, that is the number of blocks fully occupied by the prefix.
//
// To determine this number, we pass two different cleartexts to the oracle and count the number
// of identical blocks at the start of the corresponding ciphertexts.

fn full_prefix_blocks_count<T: DeterministicOracle>(oracle: &T) -> Result<usize, Error> {
    if let Some(result) = oracle
        .encrypt(&[0])?
        .chunks(BLOCK_SIZE)
        .zip(oracle.encrypt(&[1])?.chunks(BLOCK_SIZE))
        .position(|(x, y)| x != y)
    {
        Ok(result)
    } else {
        bail!("no differing blocks found, something is wrong with the provided oracle");
    }
}

// We look at the first block C not fully occupied by the prefix and fill it with a
// constant block B, say consisting of 0's.
// This part of the cleartext in oracle looks as follows:
//
//                               <------ B ------->
// prefix[?] prefix[?] prefix[?] 0 0 ... 0 || 0 0 0 suffix[0] suffix[1]
// <---------- C ------------------------>
//
// We then successively reduce the length of B until the ciphertext of C
// changes. This happens as soon as the cleartext in oracle looks as follows:
//
//                               <-- B -->
// prefix[?] prefix[?] prefix[?] 0 0 ... 0 suffix[0] || suffix[1]
// <---------- C ---------------------------------->
//
// This gives us the length of the prefix in C.
//
// We need to do this with two different constants because suffix[0] might accidentally
// coincide with the constant we have chosen.

pub fn prefix_length<T: DeterministicOracle>(oracle: &T) -> Result<usize, Error> {
    let n = full_prefix_blocks_count(oracle)?;
    let helper = |k: u8| -> Result<usize, Error> {
        let constant_block = vec![k; BLOCK_SIZE];

        let mut prev = oracle.encrypt(&constant_block)?;

        for i in 0..BLOCK_SIZE {
            let cur = oracle.encrypt(&constant_block[i + 1..])?;
            if prev.chunks(BLOCK_SIZE).nth(n) != cur.chunks(BLOCK_SIZE).nth(n) {
                return Ok(i);
            }
            prev = cur;
        }
        Ok(BLOCK_SIZE)
    };

    Ok(n * BLOCK_SIZE + std::cmp::min(helper(0)?, helper(1)?))
}

pub fn suffix_length<T: DeterministicOracle>(oracle: &T) -> Result<usize, Error> {
    Ok(prefix_plus_suffix_length(oracle)? - prefix_length(oracle)?)
}

pub fn decrypt_suffix<T: DeterministicOracle>(oracle: &T) -> Result<Vec<u8>, Error> {
    // The following input is chosen in such a way that the cleartext in oracle looks as follows:
    //
    //            input start      input end
    //                ↓                ↓
    // <-- prefix --> 0 ... 0 || 0 ... 0 suffix[0] || suffix[1] ...
    //                ↑          ↑
    //            prefix_len  prefix_blocks*BLOCK_SIZE
    //
    // The resulting ciphertext is compared to oracle([input, u]). The u yielding a match is
    // equal to suffix[0].

    let prefix_len = prefix_length(oracle)?;
    let (prefix_blocks, prefix_padding) = ceil_quotient(prefix_len, BLOCK_SIZE);
    let suffix_len = suffix_length(oracle)?;

    let mut suffix = Vec::with_capacity(suffix_len);

    let mut input = vec![0; prefix_padding + BLOCK_SIZE - 1];
    let reference_ciphertexts = (0..BLOCK_SIZE)
        .map(|left_shift| oracle.encrypt(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>, Error>>()?;

    for i in 0..suffix_len {
        let block_index = prefix_blocks + i / BLOCK_SIZE;
        let left_shift = i % BLOCK_SIZE;
        for u in 0u8..=255 {
            input.push(u);
            if reference_ciphertexts[left_shift][block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE]
                == oracle.encrypt(&input[left_shift..])?
                    [block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE]
            {
                suffix.push(u);
                break;
            }
            input.pop();
        }
    }
    Ok(suffix)
}

pub fn run() -> Result<(), Error> {
    let oracle = Oracle12::new()?;
    oracle.verify_suffix(&decrypt_suffix(&oracle)?)
}
