use crate::errors::*;

mod challenge25;
mod challenge26;
mod challenge27;
mod challenge28;
mod challenge29_30;
mod challenge31;
mod challenge32;

mod hmac_client;
mod hmac_server;

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<()>>) {
    challenges.push(challenge25::run);
    challenges.push(challenge26::run);
    challenges.push(challenge27::run);
    challenges.push(challenge28::run);
    challenges.push(challenge29_30::run29);
    challenges.push(challenge29_30::run30);
    challenges.push(challenge31::run);
    challenges.push(challenge32::run);
}
