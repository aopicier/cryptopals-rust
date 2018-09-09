use errors::*;

mod challenge01;
mod challenge02;
mod challenge03;
mod challenge04;
mod challenge05;
mod challenge06;
mod challenge07;
mod challenge08;

pub use self::challenge06::break_multibyte_xor_for_keysize;
pub use self::challenge07::read_file_to_string;

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge01::run);
    challenges.push(challenge02::run);
    challenges.push(challenge03::run);
    challenges.push(challenge04::run);
    challenges.push(challenge05::run);
    challenges.push(challenge06::run);
    challenges.push(challenge07::run);
    challenges.push(challenge08::run);
}
