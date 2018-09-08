use aes::{padding_valid, Aes128};

use errors::*;

pub fn run() -> Result<(), Error> {
    compare_eq(true, b"ICE ICE BABY\x04\x04\x04\x04".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x05\x05\x05\x05".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x01\x02\x03\x04".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x03\x03\x03".padding_valid())?;
    compare_eq(
        true,
        padding_valid(
            b"ICE ICE BABY\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",
            12,
        ).unwrap(),
    )?;
    Ok(())
}
