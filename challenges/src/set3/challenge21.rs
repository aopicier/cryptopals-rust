use crate::errors::*;
use crate::mersenne::MersenneTwister;

pub fn run() -> Result<(), Error> {
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
