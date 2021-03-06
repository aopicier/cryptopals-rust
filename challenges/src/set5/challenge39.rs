use bignum::BigNumTrait;
use bignum::OpensslBigNum as BigNum;

use rsa::Rsa;

use crate::errors::*;

pub fn run() -> Result<()> {
    let rsa = Rsa::<BigNum>::generate(512);
    let m = BigNumTrait::from_u32(42);
    compare_eq(&m, &rsa.decrypt(&rsa.encrypt(&m)))
}
