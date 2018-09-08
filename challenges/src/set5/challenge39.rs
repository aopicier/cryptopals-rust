use bignum::OpensslBigNum as BigNum;
use bignum::BigNumTrait;

use rsa::Rsa;

use errors::*;

pub fn run() -> Result<(), Error> {
    let rsa = Rsa::<BigNum>::generate(512);
    let m = BigNumTrait::from_u32(42);
    compare_eq(&m, &rsa.decrypt(&rsa.encrypt(&m)))
}

