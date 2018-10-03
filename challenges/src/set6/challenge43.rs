use crate::errors::*;

use aes::random_block;
use dsa::{compute_sha1, Dsa, DsaParams, Signature};

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

use serialize::Serialize;

pub fn compute_private_key_from_k(
    params: &DsaParams<BigNum>,
    m: &BigNum,
    &Signature { ref r, ref s }: &Signature<BigNum>,
    k: &BigNum,
) -> BigNum {
    let q = &params.q;
    let x = &(&(s * k) - m) * &r.invmod(q).unwrap();
    x.remainder(q)
}

pub fn run() -> Result<(), Error> {
    // First check that our key recovery function actually works.
    {
        let message = random_block();
        let m = BigNum::from_bytes_be(&compute_sha1(&message));
        let dsa = Dsa::generate();
        let (signature, k) = dsa.sign_insecure(&message);
        compare_eq(true, dsa.verify_signature(&message, &signature))?;

        let private_key = compute_private_key_from_k(dsa.params(), &m, &signature, &k);
        compare_eq(true, dsa.is_private_key(&private_key))?;
    }

    // Now to the actual exercise
    let params = DsaParams::default();

    let y = BigNum::from_hex_str(
        "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
         abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
         e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
         1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
         bb283e6633451e535c45513b2d33c99ea17",
    )?;

    let message = b"For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
";

    let m = BigNum::from_bytes_be(&compute_sha1(&message[..]));
    compare_eq(
        &BigNum::from_hex_str("d2d0714f014a9784047eaeccf956520045c45265")?,
        &m,
    )?;

    let signature = Signature {
        r: BigNum::from_dec_str("548099063082341131477253921760299949438196259240")?,
        s: BigNum::from_dec_str("857042759984254168557880549501802188789837994940")?,
    };

    let private_key = (0u32..=(1 << 16))
        .map(BigNumTrait::from_u32)
        .map(|k| compute_private_key_from_k(&params, &m, &signature, &k))
        .find(|x| Dsa::compute_public_key(&params, x) == y)
        .ok_or_else(|| err_msg("failed to determine private key"))?;

    let private_key_hex = private_key.to_hex_str();

    // Verify that the SHA1 of the hex representation of the private key is the one given in the
    // exercise.
    compare_eq(
        "0954edd5e0afe5542a4adf012611a91912a3ec16",
        compute_sha1(private_key_hex.as_bytes()).to_hex().as_ref(),
    )
}
