use crate::errors::*;

use dsa::{gen_range, Dsa, DsaParams, Signature};

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

pub fn fake_signature(params: &DsaParams<BigNum>, y: &BigNum) -> Signature<BigNum> {
    let p = &params.p;
    let q = &params.q;
    let z = gen_range(&BigNum::from_u32(2), q);
    let r = y.mod_exp(&z, p).remainder(q);
    let s = (&r * &z.invmod(q).unwrap()).remainder(q);
    Signature { r, s }
}

pub fn run() -> Result<()> {
    // It is not possible to fake a signature for g = 0 with our verification routine because r
    // would have to be 0. We therefore skip this part of the exercise.
    let params = DsaParams::new_with_g(BigNum::one());
    let dsa = Dsa::generate_with_params(params);

    let signature = fake_signature(dsa.params(), dsa.public_key());

    compare_eq(true, dsa.verify_signature(&b"Hello, world"[..], &signature))?;
    compare_eq(
        true,
        dsa.verify_signature(&b"Goodbye, world"[..], &signature),
    )?;
    Ok(())
}
