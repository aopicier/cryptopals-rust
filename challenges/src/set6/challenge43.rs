use errors::*;

use dsa::{DsaParams, DsaPrivate, DsaPublic, Signature};

use bignum::BigNumTrait;
use bignum::OpensslBigNum as BigNum;

pub fn run() -> Result<(), Error> {
    let params = DsaParams::generate();

    let y = BigNum::from_hex_str(
        "\
         84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
         abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
         e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
         1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
         bb283e6633451e535c45513b2d33c99ea17",
    )?;
    let public = DsaPublic { params: &params, y };
    let m = BigNum::from_hex_str("d2d0714f014a9784047eaeccf956520045c45265")?;
    let signature = Signature {
        r: BigNum::from_dec_str("548099063082341131477253921760299949438196259240")?,
        s: BigNum::from_dec_str("857042759984254168557880549501802188789837994940")?,
    };

    let zero = BigNum::zero();
    let one = BigNum::one();
    let private = (0u32..(1 << 16) + 1)
        .map(BigNumTrait::from_u32)
        .map(|k| public.secret_key_from_k(&m, &signature, &k))
        .filter(|x| x != &zero && x != &one)
        .map(|x| DsaPrivate { params: &params, x })
        .find(|private| DsaPublic::generate(private).y == public.y);

    // ~ echo -n 15fb2873d16b3e129ff76d0918fd7ada54659e49 | sha1sum
    // 0954edd5e0afe5542a4adf012611a91912a3ec16  -
    compare_eq(
        Some(BigNum::from_hex_str(
            "15fb2873d16b3e129ff76d0918fd7ada54659e49",
        )?),
        private.map(|p| p.x),
    )
}
