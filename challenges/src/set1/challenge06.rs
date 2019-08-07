use serialize::from_base64_file;
use std::path::Path;
use xor::XOR;

use super::challenge03::{break_single_byte_xor, compute_score};
use crate::errors::*;

fn hamming_distance(u: &[u8], v: &[u8]) -> Result<u32> {
    if u.len() != v.len() {
        return Err("inputs need to have the same length".into());
    }

    Ok(u.xor(v)
        .iter()
        .fold(0u32, |a, &b| a + u32::from(nonzero_bits_count(b))))
}

fn nonzero_bits_count(mut u: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        res += u % 2;
        u >>= 1;
    }
    res
}

#[test]
fn test_hamming_distance() {
    assert_eq!(
        37,
        hamming_distance(b"this is a test", b"wokka wokka!!!").unwrap() // unwrap is ok
    );
}

// We use the first four blocks of `input` and sum the pairwise distances.
fn compute_normalized_hamming_distance(input: &[u8], keysize: usize) -> f32 {
    let chunks: Vec<&[u8]> = input.chunks(keysize).take(4).collect();
    let mut distance = 0f32;
    for i in 0..4 {
        for j in i..4 {
            distance += hamming_distance(chunks[i], chunks[j]).unwrap() as f32; // unwrap is ok
        }
    }

    distance / keysize as f32
}

// Returns the three key sizes with the smallest normalized hamming distance.
fn candidate_keysizes(input: &[u8]) -> Vec<usize> {
    let count = 3;
    let mut distances: Vec<(usize, u32)> = (2..40)
        .map(|keysize| {
            (
                keysize,
                (100f32 * compute_normalized_hamming_distance(input, keysize)) as u32,
            )
        })
        .collect();

    distances.sort_by(|&(_, s), &(_, t)| s.cmp(&t));
    distances.iter().take(count).map(|x| x.0).collect()
}

fn transposed_blocks(input: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut transposed_blocks: Vec<Vec<u8>> = (0..size).map(|_| Vec::new()).collect();
    for block in input.chunks(size) {
        for (&u, bt) in block.iter().zip(transposed_blocks.iter_mut()) {
            bt.push(u);
        }
    }
    transposed_blocks
}

pub fn break_multibyte_xor_for_keysize(input: &[u8], keysize: usize) -> Vec<u8> {
    transposed_blocks(input, keysize)
        .iter()
        .map(|b| break_single_byte_xor(b))
        .collect::<Vec<u8>>()
}

fn break_multibyte_xor(input: &[u8]) -> Vec<u8> {
    // To pick the correct key from the different candidates
    // we use our scoring function based on character frequencies.
    candidate_keysizes(input)
        .iter()
        .map(|&size| break_multibyte_xor_for_keysize(input, size))
        .min_by_key(|key| compute_score(&input.xor(key)))
        .unwrap()
}

pub fn run() -> Result<()> {
    let input = from_base64_file(Path::new("data/6.txt"))?;
    let key = break_multibyte_xor(&input);
    compare_eq(b"Terminator X: Bring the noise".as_ref(), &key)
}
