use serialize::from_hex;

use mac::hmac_sha1;

use crate::errors::*;

pub fn run() -> Result<()> {
    // We only solve the exercise once, see challenge 32
    compare_eq(
        from_hex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")?,
        hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog"),
    )
}
