# cryptopals-rust
Solutions to the cryptopals (Matasano) crypto challenges in Rust

This repository contains solutions to some of the [cryptopals crypto challenges](https://cryptopals.com/) in Rust.

## Usage
Simply execute the following commands after cloning the repository:
```
cd cryptopals-rust/challenges
cargo run
```

## Disclaimer
As the purpose of these challenges is educational, I have reimplemented a lot of functionality instead of using library functions or crates. Of course these reimplementations are in no way supposed to be used for anything serious and you should always refer to an official library instead.

In particular the implementations of cryptographic algorithms found in this repository are completely insecure, in many cases even on purpose because it is part of the challenges to break those broken implementations.
