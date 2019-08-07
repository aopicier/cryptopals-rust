use rand;
use rand::Rng;

use crate::mersenne;
use crate::mersenne::MersenneTwister;

use crate::errors::*;

fn get_mersenne_twister_with_random_seed() -> MersenneTwister {
    let mut rng = rand::thread_rng();
    let seed = rng.gen();
    MersenneTwister::initialize(seed)
}

pub fn run() -> Result<()> {
    let mut mt = get_mersenne_twister_with_random_seed();
    let mut state = [0; mersenne::STATE_SIZE];
    for entry in state.iter_mut() {
        *entry = mersenne::untemper(mt.next().unwrap()); // unwrap is ok
    }
    let mut mt_clone = MersenneTwister::initialize_with_state(state);
    for _ in 0..mersenne::STATE_SIZE {
        compare_eq(mt.next(), mt_clone.next())?;
    }
    Ok(())
}
