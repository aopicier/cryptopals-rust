use helper::compute_score;

use aes::BLOCK_SIZE;
use aes::{Aes128, MODE};

use xor::XOR;

use serialize::Serialize;
use serialize::from_base64_file;
use serialize::{from_hex, from_hex_lines};

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use errors::*;

fn transposed_blocks(input: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut transposed_blocks: Vec<Vec<u8>> = (0..size).map(|_| Vec::new()).collect();
    for block in input.chunks(size) {
        for (&u, bt) in block.iter().zip(transposed_blocks.iter_mut()) {
            bt.push(u);
        }
    }
    transposed_blocks
}

fn matasano1_1() -> Result<(), Error> {
    let input_string = "49276d206b696c6c696e6720796f757220627261\
                        696e206c696b65206120706f69736f6e6f7573206\
                        d757368726f6f6d";

    compare_eq(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        &from_hex(input_string)?.to_base64(),
    )
}

fn matasano1_2() -> Result<(), Error> {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    compare_eq(
        "746865206b696420646f6e277420706c6179",
        &from_hex(input1)?.xor(&from_hex(input2)?).to_hex(),
    )
}

pub fn decrypt_single_xor(input: &[u8]) -> u8 {
    (0u8..=255)
        .into_iter()
        .min_by_key(|&u| compute_score(&input.xor(&[u])))
        .unwrap()
}

fn matasano1_3() -> Result<(), Error> {
    let input = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
    let key = decrypt_single_xor(&input);
    compare_eq(
        b"Cooking MC's like a pound of bacon".as_ref(),
        &input.xor(&[key]),
    )
}

fn matasano1_4() -> Result<(), Error> {
    let path = Path::new("data/4.txt");
    let lines = from_hex_lines(path)?;
    let result = lines
        .into_iter()
        .flat_map(|line: Vec<u8>| (0u8..128).map(move |u| line.xor(&[u])))
        .min_by_key(|cand| compute_score(cand))
        .unwrap();
    compare_eq(b"Now that the party is jumping\n".as_ref(), &result)
}

fn matasano1_5() -> Result<(), Error> {
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    let passphrase = b"ICE";
    compare_eq(
        "0b3637272a2b2e63622c2e69692a23693a2a3c632\
         4202d623d63343c2a26226324272765272a282b2f2\
         0430a652e2c652a3124333a653e2b2027630c692b2\
         0283165286326302e27282f",
        &input.xor(passphrase).to_hex(),
    )
}

fn hamming_distance(u: &[u8], v: &[u8]) -> Result<u32, Error> {
    if u.len() != v.len() {
        bail!("inputs need to have the same length");
    }

    Ok(u.xor(v)
        .iter()
        .fold(0u32, |a, &b| a + u32::from(nonzero_bits(b))))
}

fn nonzero_bits(mut u: u8) -> u8 {
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
        hamming_distance(b"this is a test", b"wokka wokka!!!").unwrap(),
        37
    );
}

fn candidate_keysizes(input: &[u8]) -> Vec<usize> {
    let score = |keysize| {
        input.chunks(2 * keysize).take(8).fold(0, |a, x| {
            a + hamming_distance(&x[..keysize], &x[keysize..]).unwrap()
        }) as f32 / keysize as f32
    };
    let mut scores: Vec<(usize, u32)> = (2..40).map(|size| (size, score(size) as u32)).collect();
    scores.sort_by(|&(_, s), &(_, t)| s.cmp(&t));
    scores.iter().take(10).map(|x| x.0).collect()
}

fn decrypt_xor(input: &[u8]) -> Vec<u8> {
    let candidate_key = |size| {
        transposed_blocks(input, size)
            .iter()
            .map(|b| decrypt_single_xor(b))
            .collect::<Vec<u8>>()
    };

    candidate_keysizes(input)
        .iter()
        .map(|&size| candidate_key(size))
        .min_by_key(|key| compute_score(&input.xor(key)))
        .unwrap()
}

fn matasano1_6() -> Result<(), Error> {
    let input = from_base64_file(Path::new("data/6.txt"))?;
    let key = decrypt_xor(&input);
    compare_eq(b"Terminator X: Bring the noise".as_ref(), &key)
}

fn matasano1_7() -> Result<(), Error> {
    let key = b"YELLOW SUBMARINE";
    let ciphertext = from_base64_file(Path::new("data/7.txt"))?;
    let cleartext = ciphertext.decrypt(key, None, MODE::ECB)?;

    //Read reference cleartext
    let path = Path::new("data/7.ref.txt");
    let mut file = File::open(&path)?;
    let mut cleartext_ref = String::new();
    file.read_to_string(&mut cleartext_ref)?;

    compare_eq(cleartext_ref.as_bytes(), &cleartext)
}

fn matasano1_8() -> Result<(), Error> {
    //Find the line with a repeating 16 byte block (<=> with a repeating 32 hex-digits block)
    let path = Path::new("data/8.txt");
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let result = reader
        .lines()
        .map(|line| line.unwrap())
        .find(|line| has_duplicates(line.as_bytes().chunks(2 * BLOCK_SIZE)));

    compare_eq(
        Some(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5\
             d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649\
             af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c\
             7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6\
             aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd2\
             83d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c\
             58386b06fba186a"
                .to_owned(),
        ),
        result,
    )
}

fn has_duplicates<T>(i: T) -> bool
where
    T: Iterator,
    <T as Iterator>::Item: Ord,
{
    let mut v: Vec<_> = i.collect();
    let len = v.len();
    v.sort();
    v.dedup();
    len != v.len()
}

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(matasano1_1);
    challenges.push(matasano1_2);
    challenges.push(matasano1_3);
    challenges.push(matasano1_4);
    challenges.push(matasano1_5);
    challenges.push(matasano1_6);
    challenges.push(matasano1_7);
    challenges.push(matasano1_8);
}
