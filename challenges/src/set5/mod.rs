use errors::*;

mod challenge33;
mod challenge34_35;
mod challenge36;
mod challenge37;
mod challenge38;
mod challenge39;
mod challenge40;

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge33::run);
    challenges.push(challenge34_35::run34);
    challenges.push(challenge34_35::run35);
    challenges.push(challenge36::run);
    challenges.push(challenge37::run);
    challenges.push(challenge38::run);
    challenges.push(challenge39::run);
    challenges.push(challenge40::run);
}
