use rand;
use rand::Rng;

use mersenne;
use mersenne::MersenneTwister;

use errors::*;

pub fn run() -> Result<(), Error> {
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
