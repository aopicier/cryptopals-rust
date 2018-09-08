use errors::*;

use dsa;
use dsa::{rand_range_safe, DsaParams, DsaPrivate, DsaPublic};

use bignum::OpensslBigNum as BigNum;
use bignum::BigNumTrait;

pub fn run() -> Result<(), Error> {
    let params = DsaParams::<BigNum>::generate();
    let private = DsaPrivate::generate(&params);
    let public = DsaPublic::generate(&private);
    // It is not possible to fake a signature for g = 0 with our verification routine because r
    // would have to be 0. We therefore skip this part of the exercise.
    let params_fake = DsaParams {
        p: params.p.clone(),
        q: params.q.clone(),
        g: BigNum::one(),
    };
    //let private_fake = DsaPrivate { params: &params_fake, x: clone(&private.x) };
    let public_fake = DsaPublic {
        params: &params_fake,
        y: public.y.clone(),
    };

    let signature = dsa::fake_signature(&public_fake);

    //Arbitrary message
    let m = rand_range_safe(&params.q);
    compare_eq(true, public_fake.verify_signature(&m, &signature))
}

