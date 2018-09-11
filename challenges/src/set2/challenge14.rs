use errors::*;

use prefix_suffix_oracles::Oracle14;

use super::challenge12::decrypt_suffix;

pub fn run() -> Result<(), Error> {
    let oracle = Oracle14::new()?;
    oracle.verify_suffix(&decrypt_suffix(&oracle)?)
}
