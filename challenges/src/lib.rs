#![cfg_attr(feature="cargo-clippy", feature(tool_lints))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::just_underscores_and_digits))]
extern crate byteorder;

extern crate aes;
extern crate bignum;
extern crate diffie_hellman;
extern crate dsa;
extern crate hmac_client;
extern crate hmac_server;
extern crate mac;
extern crate rsa;
extern crate serialize;
extern crate srp;
extern crate xor;

extern crate block_buffer;
extern crate fake_simd as simd;
extern crate md4;
extern crate num;
extern crate rand;
extern crate sha1;

#[macro_use]
extern crate failure;

pub mod errors;

pub mod set1;
pub mod set2;
pub mod set3;
pub mod set4;
pub mod set5;
pub mod set6;

pub mod mersenne;
pub mod prefix_suffix_oracles;
