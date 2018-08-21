use std;
use std::collections::HashMap;
use std::path::Path;

use rand;
use rand::Rng;

use aes::BLOCK_SIZE;
use aes::{pad, padding_valid, Aes128, MODE};

use serialize::from_base64_file;

use set1::read_file_to_string;

use xor::XOR;

use helper::ceil_div;

use errors::*;

use prefix_suffix_oracles::{DeterministicOracle, Oracle};
use prefix_suffix_oracles::{Oracle11, Oracle12, Oracle13, Oracle14, Oracle16};

fn challenge_9() -> Result<(), Error> {
    compare_eq(
        [
            89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,
        ]
            .as_ref(),
        &pad(b"YELLOW SUBMARINE".as_ref(), 20)?,
    )
}

#[test]
fn aes_128_cbc() {
    let iv = [0; BLOCK_SIZE];
    let key = b"YELLOW SUBMARINE";
    let input = b"ABCDEFGHIJKLMNOP";
    assert_eq!(
        input.as_ref(),
        &input
            .encrypt(key, Some(&iv), MODE::CBC)
            .unwrap()
            .decrypt(key, Some(&iv), MODE::CBC)
            .unwrap()[..]
    );
}

fn challenge_10() -> Result<(), Error> {
    let key = b"YELLOW SUBMARINE";
    let input = from_base64_file(Path::new("data/10.txt"))?;
    let cleartext = input.decrypt(key, Some(&[0; BLOCK_SIZE]), MODE::CBC)?;

    //Read reference cleartext
    let cleartext_ref = read_file_to_string("data/10.ref.txt")?;

    compare_eq(cleartext_ref.as_bytes(), &cleartext)
}

fn uses_ecb(oracle: &mut Oracle11) -> Result<bool, Error> {
    // Assumes that oracle prepends at most one block of jibber
    // TODO: Can we relax this condition?
    let input = vec![0; 3 * BLOCK_SIZE];
    let ciphertext = oracle.encrypt(&input)?;
    let blocks: Vec<&[u8]> = ciphertext.chunks(BLOCK_SIZE).skip(1).take(2).collect();
    Ok(blocks[0] == blocks[1])
}

fn uses_padding<T: Oracle>(oracle: &T) -> Result<bool, Error> {
    Ok((oracle.encrypt(&[0])?.len() - oracle.encrypt(&[])?.len()) % BLOCK_SIZE == 0)
}

fn prefix_plus_suffix_length<T: Oracle>(oracle: &T) -> Result<usize, Error> {
    let initial = oracle.encrypt(&[])?.len();
    if !uses_padding(oracle)? {
        return Ok(initial);
    }

    let input = [0; BLOCK_SIZE];
    //Would profit from range_inclusive
    if let Some(index) = (1..BLOCK_SIZE + 1).find(|&i| {
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

/* For an oracle prepending prefix and appending suffix to its input, this function returns
 * prefix.len()/BLOCK_SIZE, that is the number of blocks fully occupied by the prefix.
 *
 * To determine this number, we pass two different cleartexts to the oracle and count the number
 * of identical blocks at the start of the corresponding ciphertexts. */
fn prefix_blocks_count<T: DeterministicOracle>(oracle: &T) -> Result<usize, Error> {
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
    let n = prefix_blocks_count(oracle)?;
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

fn challenge_11() -> Result<(), Error> {
    let mut oracle = Oracle11::new()?;
    let uses_ecb = uses_ecb(&mut oracle)?;
    oracle.verify_solution(uses_ecb)
}

fn decrypt_suffix<T: DeterministicOracle>(oracle: &T) -> Result<Vec<u8>, Error> {
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
    let (prefix_blocks, prefix_padding) = ceil_div(prefix_len, BLOCK_SIZE);
    let suffix_len = suffix_length(oracle)?;

    let mut suffix = Vec::with_capacity(suffix_len);

    let mut input = vec![0; prefix_padding + BLOCK_SIZE - 1];
    let reference_ciphertexts = (0..BLOCK_SIZE)
        .map(|left_shift| oracle.encrypt(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>, Error>>()?;

    for i in 0..suffix_len {
        let block = prefix_blocks + i / BLOCK_SIZE;
        let left_shift = i % BLOCK_SIZE;
        for u in 0u8..=255 {
            input.push(u);
            if reference_ciphertexts[left_shift][block * BLOCK_SIZE..(block + 1) * BLOCK_SIZE]
                == oracle.encrypt(&input[left_shift..])?
                    [block * BLOCK_SIZE..(block + 1) * BLOCK_SIZE]
            {
                suffix.push(u);
                break;
            }
            input.pop();
        }
    }
    Ok(suffix)
}

fn challenge_12() -> Result<(), Error> {
    let oracle = Oracle12::new()?;
    oracle.verify_suffix(&decrypt_suffix(&oracle)?)
}

pub fn decode_profile(u: &[u8], sep: u8) -> HashMap<&[u8], &[u8]> {
    let mut p = HashMap::new();
    for pair in u.split(|&x| x == sep) {
        let mut components = pair.split(|&x| x == b'=');
        p.insert(components.next().unwrap(), components.next().unwrap_or(&[]));
    }
    p
}

/* The following function works under the single assumption that the target value "user" (to be
   replaced by "admin") is stored at the very end of the profile. */
fn challenge_13() -> Result<(), Error> {
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

fn challenge_14() -> Result<(), Error> {
    let oracle = Oracle14::new()?;
    oracle.verify_suffix(&decrypt_suffix(&oracle)?)
}

pub fn random_block() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    rng.gen_iter().take(BLOCK_SIZE).collect()
}

fn challenge_15() -> Result<(), Error> {
    compare_eq(true, b"ICE ICE BABY\x04\x04\x04\x04".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x05\x05\x05\x05".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x01\x02\x03\x04".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x03\x03\x03".padding_valid())?;
    compare_eq(
        true,
        padding_valid(
            b"ICE ICE BABY\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",
            12,
        ).unwrap(),
    )?;
    Ok(())
}

fn challenge_16() -> Result<(), Error> {
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

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge_9);
    challenges.push(challenge_10);
    challenges.push(challenge_11);
    challenges.push(challenge_12);
    challenges.push(challenge_13);
    challenges.push(challenge_14);
    challenges.push(challenge_15);
    challenges.push(challenge_16);
}
