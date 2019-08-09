use std;
use std::{error, fmt};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Debug, Clone)]
pub enum ChallengeError {
    ComparisonFailed {
        // Can this be made generic?
        expected: String,
        actual: String,
    },

    NotImplemented,

    ItemNotFound(String),

    Skipped(&'static str),
}

// This is important for other errors to wrap this one.
impl error::Error for ChallengeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChallengeError::ComparisonFailed { expected, actual } => write!(
                f,
                "Comparison failed. Expected: {}, found: {}",
                expected, actual
            ),
            ChallengeError::NotImplemented => write!(f, "Not implemented."),
            ChallengeError::ItemNotFound(item) => write!(f, "Item not found: {}", item),
            ChallengeError::Skipped(item) => write!(f, "Skipping: {}", item),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionFailed;

// This is important for other errors to wrap this one.
impl error::Error for ConnectionFailed {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl fmt::Display for ConnectionFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "connection failed")
    }
}

#[derive(Debug)]
pub struct AnnotatedError {
    pub message: String,
    pub error: Box<dyn std::error::Error + Send + Sync + 'static>,
}

// This is important for other errors to wrap this one.
impl error::Error for AnnotatedError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        Some(&*self.error)
    }
}

impl fmt::Display for AnnotatedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::needless_pass_by_value))] // False positive
pub fn compare_eq<T>(x: T, y: T) -> Result<()>
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
