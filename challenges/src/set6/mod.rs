use crate::errors::*;

mod challenge41;
mod challenge42;
mod challenge43;
mod challenge44;
mod challenge45;
mod challenge46;
mod challenge47_48;

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<()>>) {
    challenges.push(challenge41::run);
    challenges.push(challenge42::run);
    challenges.push(challenge43::run);
    challenges.push(challenge44::run);
    challenges.push(challenge45::run);
    challenges.push(challenge46::run);
    challenges.push(|| challenge47_48::run(128));
    challenges.push(|| challenge47_48::run(384));
}
