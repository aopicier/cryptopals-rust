use serialize::from_hex;

use crate::errors::*;
use mac::mac_sha1;

pub fn run() -> Result<()> {
    compare_eq(
        from_hex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")?,
        mac_sha1(b"The quick brown fox ", b"jumps over the lazy dog"),
    )
}
