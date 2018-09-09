use aes::{unpad_inplace, Aes128};

use errors::*;

pub fn run() -> Result<(), Error> {
    {
        let mut message = b"ICE ICE BABY\x04\x04\x04\x04".to_vec();
        unpad_inplace(&mut message, 16)?;
        compare_eq(b"ICE ICE BABY".as_ref(), &message)?;
    }

    compare_eq(false, b"ICE ICE BABY\x05\x05\x05\x05".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x01\x02\x03\x04".padding_valid())?;
    compare_eq(false, b"ICE ICE BABY\x03\x03\x03".padding_valid())?;

    {
        let mut message = b"ICE ICE BABY\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C".to_vec();
        unpad_inplace(&mut message, 12)?;
        compare_eq(b"ICE ICE BABY".as_ref(), &message)?;
    }

    Ok(())
}
