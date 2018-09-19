use aes::{chunks_count, BLOCK_SIZE};
use errors::*;
use std;

use prefix_suffix_oracles::Oracle12;
use prefix_suffix_oracles::{DeterministicOracle, Oracle};

use super::challenge11::uses_ecb;

fn block_size<T: Oracle>(oracle: &T) -> Result<usize, Error> {
    let mut input = Vec::new();
    let initial_len = oracle.encrypt(&input)?.len();
    loop {
        input.push(0);
        let len = oracle.encrypt(&input)?.len();
        if initial_len != len {
            return Ok(len - initial_len);
        }
    }
}

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
            // Should never happen
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
    let offset = full_prefix_blocks_count(oracle)? * BLOCK_SIZE;
    let helper = |k: u8| -> Result<usize, Error> {
        let constant_block = vec![k; BLOCK_SIZE];
        let initial = &oracle.encrypt(&constant_block)?[offset..(offset + BLOCK_SIZE)];
        for i in 0..BLOCK_SIZE {
            let cur = oracle.encrypt(&constant_block[i + 1..])?;
            if cur.len() < offset + BLOCK_SIZE || initial != &cur[offset..(offset + BLOCK_SIZE)] {
                return Ok(i);
            }
        }
        Ok(BLOCK_SIZE)
    };

    Ok(offset + std::cmp::min(helper(0)?, helper(1)?))
}

pub fn prefix_and_suffix_length<T: DeterministicOracle>(
    oracle: &T,
) -> Result<(usize, usize), Error> {
    let prefix_len = prefix_length(oracle)?;
    let suffix_len = prefix_plus_suffix_length(oracle)? - prefix_len;
    Ok((prefix_len, suffix_len))
}

pub fn decrypt_suffix<T: DeterministicOracle>(oracle: &T) -> Result<Vec<u8>, Error> {
    // The following input is chosen in such a way that the cleartext in oracle looks as follows:
    //
    //            input start      input end
    //                ↓                ↓
    // <-- prefix --> 0 ... 0 || 0 ... 0 suffix[0] || suffix[1] ...
    //                ↑          ↑
    //            prefix_len  prefix_chunks_count*BLOCK_SIZE
    //
    // The resulting ciphertext is compared to oracle([input, u]). The u yielding a match is
    // equal to suffix[0].

    ensure!(
        block_size(oracle)? == BLOCK_SIZE,
        "oracle does not use expected block size"
    );

    ensure!(uses_ecb(oracle, 0)?, "oracle does not use ECB");

    let (prefix_len, suffix_len) = prefix_and_suffix_length(oracle)?;
    let (prefix_chunks_count, prefix_fill_len) = chunks_count(prefix_len);

    let mut suffix = Vec::with_capacity(suffix_len);

    let mut input = vec![0; prefix_fill_len + BLOCK_SIZE - 1];
    let reference_ciphertexts = (0..BLOCK_SIZE)
        .map(|left_shift| oracle.encrypt(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>, Error>>()?;

    for i in 0..suffix_len {
        let block_index = prefix_chunks_count + i / BLOCK_SIZE;
        let left_shift = i % BLOCK_SIZE;
        for u in 0u8..=255 {
            input.push(u);
            if reference_ciphertexts[left_shift]
                [block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE]
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
