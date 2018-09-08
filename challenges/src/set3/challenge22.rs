use mersenne;
use mersenne::MersenneTwister;
use rand;
use rand::Rng;
use std;

use errors::*;

pub fn run() -> Result<(), Error> {
    let mut rng = rand::thread_rng();
    let seed: u16 = rng.gen();
    let mut mt = MersenneTwister::initialize(u32::from(seed));
    compare_eq(
        Some(u32::from(seed)),
        mersenne::crack_seed_from_nth(mt.nth(0).unwrap(), 0, 0..(u32::from(std::u16::MAX))),
    )
}
