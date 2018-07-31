use std;
use std::path::PathBuf;

use aes::{unpad_inplace, Aes128, AesError, BLOCK_SIZE, MODE};
use byteorder::{ByteOrder, NativeEndian};

use set1::decrypt_single_xor;
use set2::random_block;

use mersenne;
use mersenne::MersenneTwister;

use serialize::from_base64;
use serialize::from_base64_lines;

use xor::XOR;

use rand;
use rand::Rng;

use helper::ceil_div;

use errors::*;

struct Server17 {
    key: Vec<u8>,
}

impl Server17 {
    fn new() -> Self {
        Self {
            key: random_block(),
        }
    }

    fn get_session_token(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
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
        let ciphertext = input.encrypt(&self.key, Some(&iv), MODE::CBC)?;
        Ok((ciphertext, iv))
    }

    fn is_padding_valid(&self, iv: &[u8], ciphertext: &[u8]) -> Result<bool, Error> {
        //match ciphertext.decrypt(&self.key, Some(iv), MODE::CBC) {
        //    Err(aes::Error(aes::ErrorKind::InvalidPadding, _)) => Ok(false),
        //    Err(e) => Err(e.into()),
        //    _ => Ok(true),
        //}
        if let Err(error) = ciphertext.decrypt(&self.key, Some(iv), MODE::CBC) {
            if let Some(&AesError::InvalidPadding) = error.downcast_ref::<AesError>() {
                Ok(false)
            } else {
                Err(error)
            }
        } else {
            Ok(true)
        }
    }

    fn verify_solution(&self, cleartext: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<(), Error> {
        compare_eq(
            &ciphertext.decrypt(&self.key, Some(iv), MODE::CBC)?[..],
            cleartext,
        )
    }
}

fn matasano3_17() -> Result<(), Error> {
    let server = Server17::new();
    let (ciphertext, iv) = server.get_session_token()?;
    let mut cleartext = vec![0; ciphertext.len()];
    let mut prev = iv.clone();
    for (block_count, block) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
        let block_offset = block_count * BLOCK_SIZE;
        for i in (0..BLOCK_SIZE).rev() {
            let padding = (BLOCK_SIZE - i) as u8;
            prev[i + 1..].xor_inplace(&[(padding - 1) ^ padding]);
            //Awaits replacement for range_inclusive
            for u in 0u8..=255 {
                prev[i] ^= u;
                if server.is_padding_valid(&prev, block)?
                    && (i < BLOCK_SIZE - 1 || {
                        prev[i - 1] ^= 1;
                        let result = server.is_padding_valid(&prev, block)?;
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
    server.verify_solution(&cleartext, &iv, &ciphertext)
}

fn matasano3_18() -> Result<(), Error> {
    let ciphertext =
        from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")?;
    let cleartext = ciphertext.decrypt(b"YELLOW SUBMARINE", None, MODE::CTR)?;
    compare_eq(
        b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".as_ref(),
        &cleartext,
    )
}

enum Exercise {
    _19,
    _20,
}

struct Encrypter19_20 {
    key: Vec<u8>,
    exercise: Exercise,
}

impl Encrypter19_20 {
    pub fn new(exercise: Exercise) -> Self {
        Encrypter19_20 {
            key: random_block(),
            exercise,
        }
    }

    pub fn get_ciphertexts(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut input_file_path = PathBuf::from("data");
        let input_file_name = match self.exercise {
            Exercise::_19 => "19.txt",
            Exercise::_20 => "20.txt",
        };
        input_file_path.push(input_file_name);
        let cleartexts = from_base64_lines(input_file_path.as_path())?;
        cleartexts
            .iter()
            .map(|c| c.encrypt(&self.key, None, MODE::CTR))
            .collect::<Result<Vec<Vec<u8>>, Error>>()
    }

    pub fn verify_solution(&self, candidate_key: &[u8], size: usize) -> Result<(), Error> {
        // TODO: The first entry of the recovered key is wrong because the distribution of first letters
        // of sentences is very different from the overall distribution of letters in a text.
        compare_eq(
            &vec![0; size].encrypt(&self.key, None, MODE::CTR)?[1..],
            &candidate_key[1..],
        ) // encrypt or decrypt?
    }
}

fn matasano3_19_20(exercise: Exercise) -> Result<(), Error> {
    let encrypter = Encrypter19_20::new(exercise);
    let ciphertexts = encrypter.get_ciphertexts()?;
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

    encrypter.verify_solution(&key, size)
}

fn matasano3_21() -> Result<(), Error> {
    let mt = MersenneTwister::initialize(1);
    compare_eq(
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

fn matasano3_22() -> Result<(), Error> {
    let mut rng = rand::thread_rng();
    let seed: u16 = rng.gen();
    let mut mt = MersenneTwister::initialize(u32::from(seed));
    compare_eq(
        Some(u32::from(seed)),
        mersenne::crack_seed_from_nth(mt.nth(0).unwrap(), 0, 0..(u32::from(std::u16::MAX))),
    )
}

fn matasano3_23() -> Result<(), Error> {
    let mut rng = rand::thread_rng();
    let seed = rng.gen();
    let mut mt = MersenneTwister::initialize(seed);
    let mut state = [0; mersenne::STATE_SIZE];
    for entry in state.iter_mut() {
        *entry = mersenne::untemper(mt.next().unwrap());
    }
    let mut mt_clone = MersenneTwister::initialize_with_state(state);
    for _ in 0..mersenne::STATE_SIZE {
        compare_eq(mt.next(), mt_clone.next())?;
    }
    Ok(())
}

fn matasano3_24() -> Result<(), Error> {
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
    compare_eq(
        Some(u32::from(seed)),
        mersenne::crack_seed_from_nth(random_number, index, 0..(u32::from(std::u16::MAX))),
    )
}

pub fn run() {
    println!("Set 3");
    run_exercise(matasano3_17, 17);
    run_exercise(matasano3_18, 18);
    run_exercise(|| matasano3_19_20(Exercise::_19), 19);
    run_exercise(|| matasano3_19_20(Exercise::_20), 20);
    run_exercise(matasano3_21, 21);
    run_exercise(matasano3_22, 22);
    run_exercise(matasano3_23, 23);
    run_exercise(matasano3_24, 24);
}
