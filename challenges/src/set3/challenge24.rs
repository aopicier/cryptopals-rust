use byteorder::{ByteOrder, NativeEndian};
use std;

use rand;
use rand::Rng;

use mersenne;
use mersenne::MersenneTwister;

use errors::*;
use xor::XOR;

use helper::ceil_quotient;

pub fn run() -> Result<(), Error> {
    let mut rng = rand::thread_rng();
    let prefix_len: u8 = rng.gen();
    let cleartext = {
        let mut v: Vec<u8> = rng.gen_iter().take(prefix_len as usize).collect();
        v.extend_from_slice(&[b'A'; 14]);
        v
    };
    let seed: u16 = rng.gen();
    let mt = MersenneTwister::initialize(u32::from(seed));

    let mut ciphertext: Vec<u8> = Vec::new();
    let buffer = &mut [0u8; 4];

    for (c, m) in cleartext.chunks(4).zip(mt) {
        //Get underlying bytes from u32 value
        <NativeEndian as ByteOrder>::write_u32(buffer, m);
        ciphertext.append(&mut c.xor(buffer));
    }

    let (used_random_numbers_count, _) = ceil_quotient(ciphertext.len(), 4);
    let index = used_random_numbers_count - 2;
    // To recover the seed, we use the fact that the block ciphertext[4*index..4*(index+1)] was
    // encrypted with the index-th random number (counting as always from 0). As we also know the
    // plaintext at this position we can recover the random number.
    let random_number = <NativeEndian as ByteOrder>::read_u32(
        &ciphertext[4 * index..4 * (index + 1)].xor(&[b'A'; 4]),
    );
    compare_eq(
        Some(u32::from(seed)),
        mersenne::crack_seed_from_nth(random_number, index, 0..(u32::from(std::u16::MAX))),
    )
}
