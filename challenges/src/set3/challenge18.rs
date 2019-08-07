use crate::errors::*;
use aes::{Aes128, MODE};
use serialize::from_base64;

pub fn run() -> Result<()> {
    let ciphertext =
        from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")?;
    let cleartext = ciphertext.decrypt(b"YELLOW SUBMARINE", None, MODE::CTR)?;
    compare_eq(
        b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".as_ref(),
        &cleartext,
    )
}
