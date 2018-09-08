use errors::*;

use rsa::Rsa;

use bignum::BigNumTrait;
use bignum::OpensslBigNum as BigNum;
use serialize::{from_base64, Serialize};

struct Server46 {
    rsa: Rsa<BigNum>,
}

impl Server46 {
    fn new() -> Self {
        let rsa = Rsa::generate(1024);
        Server46 { rsa }
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

pub fn run() -> Result<(), Error> {
    let _1 = BigNum::one();
    let _2 = BigNum::from_u32(2);
    let server = Server46::new();
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
