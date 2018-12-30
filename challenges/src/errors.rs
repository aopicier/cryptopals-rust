use std;

pub use failure::{err_msg, Error, ResultExt};

#[derive(Debug, Fail)]
pub enum ChallengeError {
    #[fail(
        display = "Comparison failed. Expected: {}, found: {}",
        expected, actual
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

#[cfg_attr(feature = "cargo-clippy", allow(clippy::needless_pass_by_value))] // False positive
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
        }
        .into())
    }
}
