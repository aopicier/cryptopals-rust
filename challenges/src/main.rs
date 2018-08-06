extern crate challenges;
extern crate failure;
use challenges::errors::run_exercise;
use failure::Error;
use std::env;

fn main() {
    let mut challenges = Vec::<fn() -> Result<(), Error>>::new();
    challenges::set1::add_challenges(&mut challenges);
    challenges::set2::add_challenges(&mut challenges);
    challenges::set3::add_challenges(&mut challenges);
    challenges::set4::add_challenges(&mut challenges);
    challenges::set5::add_challenges(&mut challenges);
    challenges::set6::add_challenges(&mut challenges);

    let challenges_count = challenges.len();
    assert!(challenges_count <= std::u8::MAX as usize);

    match challenge_indices(challenges_count) {
        Ok(indices) => {
            for i in indices {
                run_exercise(challenges[i - 1], i as u8);
            }
        }
        Err(arg) => {
            println!(
                "Provided argument \"{}\" is invalid. Expected a number between 1 and {} ",
                arg, challenges_count
            );
        }
    }
}

fn challenge_indices(challenges_count: usize) -> Result<Vec<usize>, String> {
    let args = env::args();
    if args.len() <= 1 {
        return Ok((1..=challenges_count).collect());
    }

    let mut indices = Vec::new();
    for arg in args.into_iter().skip(1) {
        if let Ok(index) = arg.parse::<usize>() {
            if index >= 1 && index <= challenges_count {
                indices.push(index);
                continue;
            }
        }
        println!("{}", arg);
        return Err(arg);
    }
    Ok(indices)
}
