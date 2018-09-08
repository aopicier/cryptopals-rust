use errors::*;

use prefix_suffix_oracles::Oracle;
use prefix_suffix_oracles::Oracle14;

use set2::challenge12::decrypt_suffix;

// The following function works under the single assumption that the target value "user" (to be
// replaced by "admin") is stored at the very end of the profile.

pub fn run() -> Result<(), Error> {
    let oracle = Oracle14::new()?;
    oracle.verify_suffix(&decrypt_suffix(&oracle)?)
}

