use std;

pub use failure::{err_msg, Error, ResultExt};

#[derive(Debug, Fail)]
pub enum ChallengeError {
    #[fail(
        display = "Comparison failed. Expected: {}, found: {}",
        expected,
        actual
    )]
    ComparisonFailed {
        // Can this be made generic?
        expected: String,
        actual: String,
    },

    #[fail(display = "Not implemented.")]
    NotImplemented,

    #[fail(display = "Item not found: {}", _0)]
    ItemNotFound(String),

    #[fail(display = "Skipping: {}", _0)]
    Skipped(&'static str),
}

#[cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::needless_pass_by_value)
)] // False positive
pub fn compare_eq<T>(x: T, y: T) -> Result<(), Error>
where
    T: Eq + std::fmt::Debug,
{
    if x == y {
        Ok(())
    } else {
        Err(ChallengeError::ComparisonFailed {
            expected: format!("{:?}", x),
            actual: format!("{:?}", y),
        }.into())
    }
}

pub fn run_exercise<F>(exercise: F, challenge_number: u8)
where
    F: Fn() -> Result<(), Error>,
{
    match exercise() {
        Ok(_) => println!("Challenge {:02}: Success", challenge_number),
        Err(ref e) => {
            if e.downcast_ref::<ChallengeError>().is_some() {
                println!("Challenge {:02}: {}", challenge_number, e);
            } else {
                println!("Challenge {:02}: An error occured: {}", challenge_number, e);
                for cause in e.iter_causes() {
                    println!("{: <4}caused by: {}", "", cause);
                }
                let backtrace = e.backtrace().to_string();
                if !backtrace.is_empty() {
                    println!("{: <4}{}", "", e.backtrace());
                }
            }
        }
    };
}
