use std;
use std::path::Path;

use aes;
use aes::{Aes128, MODE};
use aes::BLOCK_SIZE;
use aes::unpad_inplace;

use byteorder::{ByteOrder, NativeEndian};

use set1::decrypt_single_xor;

use mersenne;
use mersenne::MersenneTwister;

use serialize::from_base64;
use serialize::from_base64_lines;

use unstable_features::all_bytes;

use xor::XOR;

use rand;
use rand::Rng;

use helper::ceil_div;

use errors::*;

fn encoder_3_17(key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let inputs = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    let mut rng = rand::thread_rng();
    let input_index = rng.gen_range(0, 10);
    let input = from_base64(inputs[input_index]).unwrap();
    let iv = random_block();
    let ciphertext = input.encrypt(key, Some(&iv), MODE::CBC)?;
    Ok((ciphertext, iv))
}

fn random_block() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    rng.gen_iter().take(BLOCK_SIZE).collect()
}

fn matasano3_17() -> Result<()> {
    let key = random_block();
    let oracle = |iv: &[u8], ciphertext: &[u8]| -> Result<bool> {
        //if let Err(Error(ErrorKind::Aes(aes::ErrorKind::InvalidPadding), _)) = ciphertext.decrypt_cbc_blocks(&key, iv).map_err(|err| err.into())
        match ciphertext.decrypt(&key, Some(iv), MODE::CBC) {
            Err(aes::Error(aes::ErrorKind::InvalidPadding, _)) => Ok(false),
            Err(e) => Err(e.into()),
            _ => Ok(true),
        }
    };

    let (ciphertext, iv) = encoder_3_17(&key)?;
    let mut cleartext = vec![0; ciphertext.len()];
    let mut prev = iv.clone();
    for (block_count, block) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
        let block_offset = block_count * BLOCK_SIZE;
        for i in (0..BLOCK_SIZE).rev() {
            let padding = (BLOCK_SIZE - i) as u8;
            prev[i + 1..].xor_inplace(&[(padding - 1) ^ padding]);
            //Awaits replacement for range_inclusive
            for u in all_bytes() {
                prev[i] ^= u;
                //let foo: Result<bool>= oracle(&prev, block);
                if oracle(&prev, block)? && (i < BLOCK_SIZE - 1 || {
                    prev[i - 1] ^= 1;
                    let result = oracle(&prev, block)?;
                    prev[i - 1] ^= 1;
                    result
                }) {
                    cleartext[block_offset + i] = padding ^ u;
                    break;
                }
                prev[i] ^= u;
            }
        }
        prev = block.to_vec();
    }
    unpad_inplace(&mut cleartext, BLOCK_SIZE as u8)?;
    compare(cleartext, ciphertext.decrypt(&key, Some(&iv), MODE::CBC)?)
}

fn matasano3_18() -> Result<()> {
    let ciphertext =
        from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")?;
    let cleartext = ciphertext.decrypt(b"YELLOW SUBMARINE", None, MODE::CTR)?;
    compare(
        b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".as_ref(),
        &cleartext,
    )
}

fn matasano3_19_20(input_file: &Path) -> Result<()> {
    let cleartexts = from_base64_lines(input_file)?;
    let secret_key = random_block();
    let ciphertexts = cleartexts
        .iter()
        .map(|c| {
            c.encrypt(&secret_key, None, MODE::CTR)
                .map_err(|err| err.into())
        })
        .collect::<Result<Vec<Vec<u8>>>>()?;
    let size = ciphertexts.iter().map(|c| c.len()).min().unwrap();
    let mut transposed_blocks: Vec<Vec<u8>> = (0..size)
        .map(|_| Vec::with_capacity(ciphertexts.len()))
        .collect();
    for ciphertext in ciphertexts {
        for (&u, bt) in ciphertext[..size].iter().zip(transposed_blocks.iter_mut()) {
            bt.push(u);
        }
    }
    let key = transposed_blocks
        .iter()
        .map(|b| decrypt_single_xor(b))
        .collect::<Vec<u8>>();
    //TODO: The first entry of the recovered key is wrong because the distribution of first letters
    //of sentences is very different from the overall distribution of letters in a text.
    compare(
        &vec![0; size].encrypt(&secret_key, None, MODE::CTR)?[1..],
        &key[1..],
    ) // encrypt or decrypt?
}

fn matasano3_21() -> Result<()> {
    let mt = MersenneTwister::initialize(1);
    compare(
        vec![
            1_791_095_845,
            4_282_876_139,
            3_093_770_124,
            4_005_303_368,
            491_263,
            550_290_313,
            1_298_508_491,
            4_290_846_341,
            630_311_759,
            1_013_994_432,
        ],
        mt.take(10).collect::<Vec<u32>>(),
    )
}

fn matasano3_22() -> Result<()> {
    let mut rng = rand::thread_rng();
    let seed: u16 = rng.gen();
    let mut mt = MersenneTwister::initialize(u32::from(seed));
    compare(
        Some(u32::from(seed)),
        mersenne::crack_seed_from_nth(mt.nth(0).unwrap(), 0, 0..(u32::from(std::u16::MAX))),
    )
}

fn matasano3_23() -> Result<()> {
    let mut rng = rand::thread_rng();
    let seed = rng.gen();
    let mut mt = MersenneTwister::initialize(seed);
    let mut state = [0; mersenne::STATE_SIZE];
    for entry in state.iter_mut() {
        *entry = mersenne::untemper(mt.next().unwrap());
    }
    let mut mt_clone = MersenneTwister::initialize_with_state(state);
    for _ in 0..mersenne::STATE_SIZE {
        compare(mt.next(), mt_clone.next())?;
    }
    Ok(())
}

fn matasano3_24() -> Result<()> {
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

    let (used_random_numbers_count, _) = ceil_div(ciphertext.len(), 4);
    let index = used_random_numbers_count - 2;
    // To recover the seed, we use the fact that the block ciphertext[4*index..4*(index+1)] was
    // encrypted with the index-th random number (counting as always from 0). As we also know the
    // plaintext at this position we can recover the random number.
    let random_number = <NativeEndian as ByteOrder>::read_u32(
        &ciphertext[4 * index..4 * (index + 1)].xor(&[b'A'; 4]),
    );
    compare(
        Some(u32::from(seed)),
        mersenne::crack_seed_from_nth(random_number, index, 0..(u32::from(std::u16::MAX))),
    )
}

pub fn run() {
    println!("Set 3");
    //matasano3_17();
    //matasano3_18();
    //matasano3_19_20(Path::new("data/19.txt"));
    //matasano3_19_20(Path::new("data/20.txt"));
    //matasano3_21();
    //matasano3_22();
    //matasano3_23();
    //matasano3_24();

    run_exercise(matasano3_17, 17);
    run_exercise(matasano3_18, 18);
    run_exercise(|| matasano3_19_20(Path::new("data/19.txt")), 19);
    run_exercise(|| matasano3_19_20(Path::new("data/20.txt")), 20);
    run_exercise(matasano3_21, 21);
    run_exercise(matasano3_22, 22);
    run_exercise(matasano3_23, 23);
    run_exercise(matasano3_24, 24);
}
