use crate::errors::*;

use rsa::Rsa;

use bignum::BigNumTrait;
use bignum::OpensslBigNum as BigNum;
use serialize::{from_base64, Serialize};

struct Server {
    rsa: Rsa<BigNum>,
}

impl Server {
    fn new() -> Self {
        let rsa = Rsa::generate(1024);
        Server { rsa }
    }

    fn n(&self) -> &BigNum {
        self.rsa.n()
    }

    fn _2_encrypted(&self) -> BigNum {
        let _2 = BigNum::from_u32(2);
        self.rsa.encrypt(&_2)
    }

    fn get_ciphertext(&self) -> Result<BigNum, Error> {
        let cleartext = from_base64(
            "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IG\
             Fyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==",
        )?.to_hex();
        let m = BigNum::from_hex_str(&cleartext)?;
        Ok(self.rsa.encrypt(&m))
    }

    fn oracle(&self, ciphertext: &BigNum) -> bool {
        let _0 = BigNum::zero();
        let _2 = BigNum::from_u32(2);
        &self.rsa.decrypt(ciphertext) % &_2 == _0
    }

    fn verify_solution(&self, cleartext: &BigNum, ciphertext: &BigNum) -> Result<(), Error> {
        compare_eq(&self.rsa.decrypt(ciphertext), cleartext)
    }
}

// `oracle` tells us whether the cleartext corresponding to a ciphertext is even or odd.
// Let c be an arbitrary ciphertext with corresponding cleartext m. Then the cleartext
// corresponding to enc(2)*c is 2m % n. As n is odd, this is even if and only if 2m < n, so
// (*) oracle(enc(2) * c) == true <=> 2m < n.
//
// Now assume that
// (**) (l-1) * n <= 2^k * m < l * n for some k >= 0 and some 1 <= l <= 2^k.
// Of course then also (2l - 2) * n <= 2^(k+1) * m < 2l * n.
// We want to find how on which side of (2l - 1) * n the cleartext m is lying.
//
// The cleartext corresponding to enc(2^k) * c is
// 2^k * m mod n = 2^k * m - (l-1) * n.
// Applying (*) for enc(2^k) * c instead of c gives
// oracle(enc(2^(k+1)) * c) == true <=> 2 * (2^k * m - (l-1) * n) < n <=> 2^(k+1) * m < (2l-1)n.
// This allows us to pass from k to k+1 in (**) and iteratively we obtain more and more precise
// bounds for m. For k = `number of bits in n` we obtain equality.

pub fn run() -> Result<(), Error> {
    let _1 = BigNum::one();
    let _2 = BigNum::from_u32(2);

    let server = Server::new();
    let _2_enc = server._2_encrypted();
    let n = server.n();
    let k = n.bits() as usize;

    let ciphertext = server.get_ciphertext()?;
    let mut c = ciphertext.clone();
    let mut l = BigNum::one();
    for _ in 0..k {
        c = &c * &_2_enc;
        l = &l * &_2;
        if server.oracle(&c) {
            l = &l - &_1;
        }
    }
    let cleartext = (n * &l).rsh(k);
    server.verify_solution(&cleartext, &ciphertext)
}
