use errors::*;

mod challenge09;
mod challenge10;
mod challenge11;
mod challenge12;
mod challenge13;
mod challenge14;
mod challenge15;
mod challenge16;

pub use self::challenge12::{prefix_and_suffix_length, prefix_length};

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge09::run);
    challenges.push(challenge10::run);
    challenges.push(challenge11::run);
    challenges.push(challenge12::run);
    challenges.push(challenge13::run);
    challenges.push(challenge14::run);
    challenges.push(challenge15::run);
    challenges.push(challenge16::run);
}
