use crate::errors::*;
use aes::pad_inplace;

pub fn run() -> Result<(), Error> {
    let mut input = b"YELLOW SUBMARINE".to_vec();
    pad_inplace(&mut input, 20)?;
    compare_eq(
        [
            89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,
        ]
        .as_ref(),
        &input,
    )
}
