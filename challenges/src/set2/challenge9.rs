use aes::pad;
use errors::*;

pub fn run() -> Result<(), Error> {
    compare_eq(
        [
            89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,
        ]
            .as_ref(),
        &pad(b"YELLOW SUBMARINE".as_ref(), 20)?,
    )
}
