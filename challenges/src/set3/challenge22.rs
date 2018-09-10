use mersenne::MersenneTwister;
use rand;
use rand::Rng;
use std;

use errors::*;

pub fn crack_seed_from_nth(u: u32, n: usize, candidates: impl Iterator<Item=u32>) -> Option<u32> {
    // Unfortunately we use brute force here. Is there an analytic attack?
    for candidate in candidates {
        if u == MersenneTwister::initialize(candidate).nth(n).unwrap() {
            return Some(candidate);
        }
    }
    None
}

pub fn run() -> Result<(), Error> {
    let mut rng = rand::thread_rng();

    // The secret seed unknown to the attacker
    let seed: u16 = rng.gen();

    let mut mt = MersenneTwister::initialize(u32::from(seed));
    let n = 0;
    compare_eq(
        Some(u32::from(seed)),
        crack_seed_from_nth(mt.nth(n).unwrap(), n, 0..(u32::from(std::u16::MAX))), // unwrap is ok
    )
}
