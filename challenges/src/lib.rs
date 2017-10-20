//#![feature(box_syntax)]
//#![feature(collections)]
//#![feature(core)]
//#![feature(custom_attribute)]
//#![feature(slice_patterns)]

//extern crate ascii;
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
extern crate unstable_features;
extern crate xor;

extern crate num;
extern crate rand;
extern crate sha1;

#[macro_use]
extern crate error_chain;

#[macro_use]
mod errors;

pub mod set1;
pub mod set2;
pub mod set3;
pub mod set4;
pub mod set5;
pub mod set6;

pub mod helper;
pub mod mersenne;
pub mod prefix_suffix_oracles;
