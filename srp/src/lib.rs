#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::just_underscores_and_digits)
)]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::many_single_char_names)
)]

extern crate bignum;
extern crate byteorder;

#[macro_use]
extern crate failure;
extern crate mac;
extern crate num;
extern crate rand;
extern crate sha2;

pub mod communication;

#[allow(non_snake_case)]
pub mod algo;

#[allow(non_snake_case)]
pub mod client;

#[allow(non_snake_case)]
pub mod mitm;

#[allow(non_snake_case)]
pub mod server;
