use errors::*;

mod challenge1;
mod challenge2;
mod challenge3;
mod challenge4;
mod challenge5;
mod challenge6;
mod challenge7;
mod challenge8;

pub use self::challenge3::break_single_byte_xor;
pub use self::challenge7::read_file_to_string;

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge1::run);
    challenges.push(challenge2::run);
    challenges.push(challenge3::run);
    challenges.push(challenge4::run);
    challenges.push(challenge5::run);
    challenges.push(challenge6::run);
    challenges.push(challenge7::run);
    challenges.push(challenge8::run);
}
