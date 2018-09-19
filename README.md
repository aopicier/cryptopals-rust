# cryptopals-rust
Solutions to the cryptopals (Matasano) crypto challenges in Rust

This repository contains solutions to some of the [cryptopals crypto challenges](https://cryptopals.com/) in Rust.

## Usage
Simply execute the following commands after cloning the repository:
```
cd cryptopals-rust/challenges
cargo run
```
This will run all challenges in the repository. It is also possible to only run a subset of the challenges. The following invocation will run challenges 7, 13 and 47:
```
cargo run 7 13 47
```

## Disclaimer
As the purpose of these challenges is educational, I have reimplemented a lot of functionality instead of using library functions or crates. Of course these reimplementations are in no way supposed to be used for anything serious and you should always refer to an official library instead.

In particular the implementations of cryptographic algorithms found in this repository are completely insecure, in many cases even on purpose because it is part of the challenges to break those broken implementations.
