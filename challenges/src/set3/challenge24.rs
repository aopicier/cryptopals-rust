use byteorder::{ByteOrder, LittleEndian};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;

use crate::mersenne::MersenneTwister;

use crate::errors::*;
use xor::XOR;

use super::challenge22::crack_seed_from_nth;

fn get_ciphertext(seed: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let prefix_len: u8 = rng.gen();
    let cleartext = {
        let mut v: Vec<u8> = rng.gen_iter().take(prefix_len as usize).collect();
        v.extend_from_slice(&[b'A'; 14]);
        v
    };
    let mt = MersenneTwister::initialize(seed);

    let mut ciphertext = Vec::new();
    let buffer = &mut [0u8; 4];

    for (c, m) in cleartext.chunks(4).zip(mt) {
        //Get underlying bytes from u32 value
        <LittleEndian as ByteOrder>::write_u32(buffer, m);
        ciphertext.append(&mut c.xor(buffer));
    }
    ciphertext
}

fn seed_from_ciphertext() -> Result<()> {
    let mut rng = rand::thread_rng();

    // The secret seed unknown to the attacker
    let seed: u16 = rng.gen();

    let ciphertext = get_ciphertext(u32::from(seed));

    // Get index of the last full block of size 4 in ciphertext
    let index = ciphertext.len() / 4 - 1;

    // To recover the seed, we use the fact that the block ciphertext[4*index..4*(index+1)] was
    // encrypted with the index-th random number (counting as always from 0). As we also know the
    // plaintext at this position we can recover the random number.
    let random_number = <LittleEndian as ByteOrder>::read_u32(
        &ciphertext[4 * index..4 * (index + 1)].xor(&[b'A'; 4]),
    );

    compare_eq(
        Some(u32::from(seed)),
        crack_seed_from_nth(random_number, index, 0..(u32::from(std::u16::MAX))),
    )
}

// Note: The following size needs to be divisible by 4 for the following code
// to work correctly.

// We work with a 128 bit token
const TOKEN_SIZE: usize = 16;

fn get_token_from_seed(seed: u32) -> [u8; TOKEN_SIZE] {
    assert!(TOKEN_SIZE % 4 == 0);

    let mut token = [0u8; TOKEN_SIZE];

    let mt = MersenneTwister::initialize(seed);
    for (c, m) in token.chunks_mut(4).zip(mt) {
        //Get underlying bytes from u32 value
        <LittleEndian as ByteOrder>::write_u32(c, m);
    }

    token
}

// We use seconds since the epoch to represent time as an u32
fn get_current_time_as_u32() -> Result<u32> {
    let seconds_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if seconds_since_epoch > u64::from(std::u32::MAX) {
        return Err("Hello dear people of the year 2038.".into());
    }

    Ok(seconds_since_epoch as u32)
}

fn is_product_of_mersenne_seeded_with_time(token: [u8; TOKEN_SIZE]) -> Result<bool> {
    let now = get_current_time_as_u32()?;

    // The function crack_seed_from_nth also uses brute force, so we can as well just
    // brute force the entire token.
    for i in 0..300 {
        if token == get_token_from_seed(now - i) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn password_reset_token() -> Result<()> {
    let now = get_current_time_as_u32()?;

    let token = get_token_from_seed(now);
    compare_eq(true, is_product_of_mersenne_seeded_with_time(token)?)?;

    compare_eq(
        false,
        is_product_of_mersenne_seeded_with_time([0; TOKEN_SIZE])?,
    )?;
    Ok(())
}

pub fn run() -> Result<()> {
    seed_from_ciphertext()?;
    password_reset_token()?;
    Ok(())
}
