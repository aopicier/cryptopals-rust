use rand;
use rand::Rng;

use aes::BLOCK_SIZE;
use errors::*;

mod challenge9;
mod challenge10;
mod challenge11;
mod challenge12;
mod challenge13;
mod challenge14;
mod challenge15;
mod challenge16;

// TODO Move somewhere else
pub fn random_block() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    rng.gen_iter().take(BLOCK_SIZE).collect()
}

pub use self::challenge12::prefix_length;

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge9::run);
    challenges.push(challenge10::run);
    challenges.push(challenge11::run);
    challenges.push(challenge12::run);
    challenges.push(challenge13::run);
    challenges.push(challenge14::run);
    challenges.push(challenge15::run);
    challenges.push(challenge16::run);
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

