use self::challenge19_20::Exercise;
use crate::errors::*;

mod challenge17;
mod challenge18;
mod challenge19_20;
mod challenge21;
mod challenge22;
mod challenge23;
mod challenge24;

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge17::run);
    challenges.push(challenge18::run);
    challenges.push(|| challenge19_20::run(Exercise::_19));
    challenges.push(|| challenge19_20::run(Exercise::_20));
    challenges.push(challenge21::run);
    challenges.push(challenge22::run);
    challenges.push(challenge23::run);
    challenges.push(challenge24::run);
}
