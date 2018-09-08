use errors::*;

use rsa::Rsa;

use bignum::BigNumTrait;
use bignum::OpensslBigNum as BigNum;

pub fn run() -> Result<(), Error> {
    let bits = 512;
    let rsa = Rsa::<BigNum>::generate(bits);

    let m = BigNumTrait::gen_random(bits - 1);
    let c = rsa.encrypt(&m);

    let oracle = |x: &BigNum| -> Option<BigNum> {
        if *x == c {
            return None;
        }
        Some(rsa.decrypt(x))
    };

    let s = BigNum::gen_random(bits - 1);
    //TODO We should check that s > 1 and that s and rsa.n() have no common divisors
    let t = s
        .invmod(rsa.n())
        .ok_or_else(|| err_msg("s and n are not coprime"))?;

    let c2 = &(&c * &rsa.encrypt(&s)) % rsa.n();
    let m2 = oracle(&c2).ok_or_else(|| err_msg("wrong input to oracle"))?;
    compare_eq(m, &(&m2 * &t) % rsa.n())
}
