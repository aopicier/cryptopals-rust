#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::just_underscores_and_digits)
)]

extern crate aes;
extern crate bignum;
extern crate byteorder;
extern crate failure;
extern crate num;
extern crate rand;
extern crate result;
extern crate sha1;

pub mod algo;
pub mod communication;
pub mod handshake;
pub mod mitm_handshake;
pub mod mitm_session;
pub mod session;
