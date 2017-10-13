use std;
use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use rand;
use rand::Rng;

use aes::{pad, padding_valid, Aes128, MODE};
use aes::BLOCK_SIZE;

use serialize::from_base64;
use serialize::from_base64_file;

use unstable_features::all_bytes;
use unstable_features::MoveFrom;

use xor::XOR;

use helper::ceil_div;

use errors::*;

fn matasano2_9() -> Result<()> {
    compare(
        [
            89,
            69,
            76,
            76,
            79,
            87,
            32,
            83,
            85,
            66,
            77,
            65,
            82,
            73,
            78,
            69,
            4,
            4,
            4,
            4,
        ].as_ref(),
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

fn matasano2_10() -> Result<()> {
    let key = b"YELLOW SUBMARINE";
    let input = from_base64_file(Path::new("data/10.txt"))?;
    let cleartext = input.decrypt(key, Some(&[0; BLOCK_SIZE]), MODE::CBC)?;

    //Read reference cleartext
    let path = Path::new("data/10.ref.txt");
    let mut file = File::open(&path)?;
    let mut cleartext_ref = String::new();
    file.read_to_string(&mut cleartext_ref)?;

    compare(cleartext_ref.as_bytes(), &cleartext)
}

fn oracle_11(u: &[u8], use_ecb: bool) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut cleartext = Vec::with_capacity(u.len() + 20);
    let key = random_block();
    let prefix_len = rng.gen_range(5, 11);
    let prefix: Vec<u8> = rng.gen_iter().take(prefix_len).collect();
    let suffix_len = rng.gen_range(5, 11);
    let suffix: Vec<u8> = rng.gen_iter().take(suffix_len).collect();

    cleartext.extend_from_slice(&prefix);
    cleartext.extend_from_slice(u);
    cleartext.extend_from_slice(&suffix);
    if use_ecb {
        cleartext
            .encrypt(&key, None, MODE::ECB)
            .map_err(|err| err.into())
    } else {
        let iv = random_block();
        cleartext
            .encrypt(&key, Some(&iv), MODE::CBC)
            .map_err(|err| err.into())
    }
}

fn uses_ecb<F>(oracle: &F) -> Result<bool>
where
    F: Fn(&[u8]) -> Result<Vec<u8>>,
{
    //Assumes that oracle prepends at most one block of jibber
    //TODO: Can we relax this condition?
    let input = vec![0; 3 * BLOCK_SIZE];
    let ciphertext = oracle(&input)?;
    let blocks: Vec<&[u8]> = ciphertext.chunks(BLOCK_SIZE).skip(1).take(2).collect();
    Ok(blocks[0] == blocks[1])
}

fn prefix_plus_suffix_length<F>(oracle: &F) -> Result<usize>
where
    F: Fn(&[u8]) -> Result<Vec<u8>>,
{
    let initial = oracle(&[])?.len();
    let input = [0; BLOCK_SIZE];
    //Would profit from range_inclusive
    if let Some(index) = (1..BLOCK_SIZE + 1).find(|&i| {
        if let Ok(ciphertext) = oracle(&input[BLOCK_SIZE - i..]) {
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
 * prefix.len()/BLOCK_SIZE, that is the number of blocks fully occupied by the prefix. */
fn prefix_blocks_count<F>(oracle: &F) -> Result<usize>
where
    F: Fn(&[u8]) -> Result<Vec<u8>>,
{
    if let Some(result) = oracle(&[0])?
        .chunks(BLOCK_SIZE)
        .zip(oracle(&[1])?.chunks(BLOCK_SIZE))
        .position(|(x, y)| x != y)
    {
        Ok(result)
    } else {
        bail!("no differing blocks found, something is wrong with the provided oracle");
    }
}

pub fn prefix_length<F>(oracle: &F) -> Result<usize>
where
    F: Fn(&[u8]) -> Result<Vec<u8>>,
{
    let n = prefix_blocks_count(oracle)?;
    let helper = |k: u8| -> Result<usize> {
        let u = vec![k; BLOCK_SIZE];

        let mut prev_u = oracle(&u)?;

        for i in 0..BLOCK_SIZE {
            let cur_u = oracle(&u[i + 1..])?;
            if prev_u.chunks(BLOCK_SIZE).nth(n) != cur_u.chunks(BLOCK_SIZE).nth(n) {
                return Ok(i);
            }
            prev_u = cur_u;
        }
        Ok(BLOCK_SIZE)
    };

    Ok(n * BLOCK_SIZE + std::cmp::min(helper(0)?, helper(1)?))
}

fn suffix_length<F>(oracle: &F) -> Result<usize>
where
    F: Fn(&[u8]) -> Result<Vec<u8>>,
{
    Ok(prefix_plus_suffix_length(oracle)? - prefix_length(oracle)?)
}

#[test]
fn test_length_functions() {
    let key = random_block();
    let mut prefix = Vec::new();
    let mut suffix = Vec::new();
    for _ in 0..64 {
        for _ in 0..64 {
            {
                let oracle = |u: &[u8]| oracle_generator(&key, &prefix, u, &suffix, MODE::CTR);
                println!("{}", prefix.len());
                println!("{}", prefix_length(&oracle).unwrap());
                assert!(prefix.len() == prefix_length(&oracle).unwrap());
                //assert!(suffix.len() == suffix_length(&oracle).unwrap());
            }
            suffix.push(1);
        }
        suffix.clear();
        prefix.push(0);
    }
}


fn matasano2_11() -> Result<()> {
    let mut rng = rand::thread_rng();
    let use_ecb = rng.gen();
    compare(use_ecb, uses_ecb(&|u| oracle_11(u, use_ecb))?)
}

pub fn oracle_generator(
    key: &[u8],
    prefix: &[u8],
    u: &[u8],
    suffix: &[u8],
    mode: MODE,
) -> Result<Vec<u8>> {
    let mut cleartext = Vec::with_capacity(prefix.len() + u.len() + suffix.len());
    cleartext.extend_from_slice(prefix);
    cleartext.extend_from_slice(u);
    cleartext.extend_from_slice(suffix);

    // Only setting iv here depending on the mode seems to be difficult because of type and/or lifetime
    // issues with Option<&[u8]>.
    match mode {
        MODE::CBC => cleartext.encrypt(key, Some(&[0; BLOCK_SIZE]), mode),
        _ => cleartext.encrypt(key, None, mode),
    }.map_err(|err| err.into())
}

fn decrypt_suffix<F>(oracle: &F) -> Result<Vec<u8>>
where
    F: Fn(&[u8]) -> Result<Vec<u8>>,
{
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
        .map(|left_shift| oracle(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>>>()?;

    for i in 0..suffix_len {
        let block = prefix_blocks + i / BLOCK_SIZE;
        //let block_range = block*BLOCK_SIZE .. (block + 1)*BLOCK_SIZE;
        let left_shift = i % BLOCK_SIZE;
        for u in all_bytes() {
            input.push(u);
            if reference_ciphertexts[left_shift][block * BLOCK_SIZE..(block + 1) * BLOCK_SIZE]
                == oracle(&input[left_shift..])?[block * BLOCK_SIZE..(block + 1) * BLOCK_SIZE]
            {
                suffix.push(u);
                break;
            }
            input.pop();
        }
    }
    Ok(suffix)
}

fn matasano2_12() -> Result<()> {
    let key = random_block();

    let suffix = from_base64(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv\
         d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvb\
         iBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW\
         91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
    )?;

    let oracle = |u: &[u8]| oracle_generator(&key, &[], u, &suffix, MODE::ECB);
    compare(&suffix, &decrypt_suffix(&oracle)?)
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
fn matasano2_13() -> Result<()> {
    let key = random_block();
    let oracle = |email: &[u8]| {
        // Exclude '&' and '='
        if email
            .iter()
            .any(|&c| !c.is_ascii() || c == b'&' || c == b'=')
        {
            panic!("Invalid input.");
        }

        let prefix = b"email=";
        let suffix = b"&uid=10&role=user";
        oracle_generator(&key, prefix, email, suffix, MODE::ECB)
    };

    let prefix_len = prefix_length(&oracle)?;
    let (prefix_blocks, prefix_padding) = ceil_div(prefix_len, BLOCK_SIZE);
    let target_cleartext = b"admin".pad();
    let mut input = vec![0; prefix_padding];
    input.extend_from_slice(&target_cleartext);
    let target_last_block = oracle(&input)?.split_off(prefix_blocks * BLOCK_SIZE);

    let (blocks, padding) = ceil_div(prefix_plus_suffix_length(&oracle)?, BLOCK_SIZE);
    let mut ciphertext = oracle(&vec![0; padding + "user".len()])?;
    compare((blocks + 1) * BLOCK_SIZE, ciphertext.len())?;

    ciphertext[blocks * BLOCK_SIZE..].move_from2(target_last_block, 0, BLOCK_SIZE);

    compare(
        Some(b"admin".as_ref()),
        decode_profile(&ciphertext.decrypt(&key, None, MODE::ECB)?, b'&').remove(b"role".as_ref()),
    )
}

fn matasano2_14() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key: Vec<u8> = rng.gen_iter().take(BLOCK_SIZE).collect();
    let prefix_len = rng.gen_range(1, 200);
    let prefix: Vec<u8> = rng.gen_iter().take(prefix_len).collect();

    let suffix = from_base64(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv\
         d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvb\
         iBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW\
         91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
    )?;

    let oracle = |u: &[u8]| oracle_generator(&key, &prefix, u, &suffix, MODE::ECB);

    compare(&suffix, &decrypt_suffix(&oracle)?)
}

pub fn random_block() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    rng.gen_iter().take(BLOCK_SIZE).collect()
}

fn matasano2_15() -> Result<()> {
    compare(true, b"ICE ICE BABY\x04\x04\x04\x04".padding_valid())?;
    compare(false, b"ICE ICE BABY\x05\x05\x05\x05".padding_valid())?;
    compare(false, b"ICE ICE BABY\x01\x02\x03\x04".padding_valid())?;
    compare(false, b"ICE ICE BABY\x03\x03\x03".padding_valid())?;
    compare(
        true,
        padding_valid(
            b"ICE ICE BABY\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",
            12,
        ).unwrap(),
    )?;
    Ok(())
}

fn matasano2_16() -> Result<()> {
    let key = random_block();
    let oracle = |input: &[u8]| {
        // Exclude ';' and '='
        if input
            .iter()
            .any(|&c| !c.is_ascii() || c == b';' || c == b'=')
        {
            panic!("Invalid input.");
        }

        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        oracle_generator(&key, prefix, input, suffix, MODE::CBC)
    };


    let (blocks, padding) = ceil_div(prefix_plus_suffix_length(&oracle)?, BLOCK_SIZE);
    let mut ciphertext = oracle(&vec![0; padding])?;
    compare((blocks + 1) * BLOCK_SIZE, ciphertext.len())?;

    let target_last_block = b";admin=true".pad();
    let current_last_block = vec![BLOCK_SIZE as u8; BLOCK_SIZE];
    let attack_bitflip = target_last_block.xor(&current_last_block);

    // Flip the next to last block
    ciphertext[(blocks - 1) * BLOCK_SIZE..blocks * BLOCK_SIZE].xor_inplace(&attack_bitflip);

    // The flipped next to last block will decrypt to arbitrary cleartext. Depending on the precise
    // implementation of decode_profile, this might cause problems, because this cleartext could
    // for example contain `;foo;`, or `foo=bar=baz`. For now we rely on the fact that
    // decode_profile accepts such inputs.

    compare(
        Some(b"true".as_ref()),
        decode_profile(
            &ciphertext.decrypt(&key, Some(&[0; BLOCK_SIZE]), MODE::CBC)?,
            b';',
        ).remove(b"admin".as_ref()),
    )
}

pub fn run() {
    println!("Set 2");
    run_exercise(matasano2_9, 9);
    run_exercise(matasano2_10, 10);
    run_exercise(matasano2_11, 11);
    run_exercise(matasano2_12, 12);
    run_exercise(matasano2_13, 13);
    run_exercise(matasano2_14, 14);
    run_exercise(matasano2_15, 15);
    run_exercise(matasano2_16, 16);
}
