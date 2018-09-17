#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::many_single_char_names)
)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::new_without_default))]

extern crate bignum;
extern crate digest;
extern crate num_traits;
extern crate rsa;
extern crate sha1;

use digest::Digest;
use num_traits::NumOps;

pub struct Dsa<T> {
    params: DsaParams<T>,
    x: T,
    y: T,
}

impl<T> Dsa<T>
where
    T: bignum::BigNumTrait + bignum::BigNumExt,
    for<'a1, 'a2> &'a1 T: NumOps<&'a2 T, T>,
{
    pub fn new() -> Self {
        let params = DsaParams::new();
        Self::new_with_params(params)
    }

    pub fn new_with_params(params: DsaParams<T>) -> Self {
        let x = gen_range(&T::from_u32(2), &params.q);
        let y = Self::compute_public_key(&params, &x);
        Dsa { params, x, y }
    }

    pub fn params(&self) -> &DsaParams<T> {
        &self.params
    }

    pub fn public_key(&self) -> &T {
        &self.y
    }

    // Make it possible to test whether we have correctly cracked the private key without revealing
    // it.
    pub fn is_private_key(&self, private_key: &T) -> bool {
        &self.x == private_key
    }

    pub fn sign(&self, message: &[u8]) -> Signature<T> {
        self.sign_insecure(message).0
    }

    // We only leak k for testing purposes. It is of course NOT part of the signature.
    pub fn sign_insecure(&self, message: &[u8]) -> (Signature<T>, T) {
        let zero = T::zero();
        let p = &self.params.p;
        let q = &self.params.q;
        let g = &self.params.g;

        let m = &T::from_bytes_be(&compute_sha1(message));

        let mut k: T;
        let mut r: T;
        let mut s: T;
        loop {
            k = gen_range(&T::from_u32(2), q);
            r = g.mod_exp(&k, p);
            r = r.remainder(q);
            if r == zero {
                continue;
            }
            s = &k.invmod(q).unwrap() * &(m + &(&r * &self.x)); // unwrap is ok
            s = s.remainder(q);
            if s == zero {
                continue;
            }
            break;
        }
        (Signature { r, s }, k)
    }

    pub fn verify_signature(
        &self,
        message: &[u8],
        &Signature { ref r, ref s }: &Signature<T>,
    ) -> bool {
        let zero = T::zero();
        let p = &self.params.p;
        let q = &self.params.q;
        let g = &self.params.g;
        if *r <= zero || r >= q || *s <= zero || s >= q {
            return false;
        }

        let m = &T::from_bytes_be(&compute_sha1(message));

        let w = T::invmod(s, q).unwrap(); // unwrap is ok
        let u1 = T::remainder(&(m * &w), q);
        let u2 = T::remainder(&(r * &w), q);
        let v1 = g.mod_exp(&u1, p);
        let v2 = self.y.mod_exp(&u2, p);
        let v = T::remainder(&T::remainder(&(&v1 * &v2), p), q);
        &v == r
    }

    pub fn compute_public_key(params: &DsaParams<T>, x: &T) -> T {
        params.g.mod_exp(x, &params.p)
    }
}

pub fn gen_range<T: bignum::BigNumTrait>(lower: &T, upper: &T) -> T
where
    T: bignum::BigNumTrait + bignum::BigNumExt,
    for<'b> &'b T: NumOps<&'b T, T>,
{
    assert!(lower < upper);
    lower + &T::gen_below(&(upper - lower))
}

pub struct DsaParams<T> {
    pub p: T,
    pub q: T,
    pub g: T,
}

impl<T: bignum::BigNumTrait> DsaParams<T> {
    pub fn new() -> Self {
        let g = T::from_hex_str(
            "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8f\
             a4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e\
             0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b\
             3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9f\
             c95302291",
        ).unwrap(); // unwrap is ok

        Self::new_with_g(g)
    }

    pub fn new_with_g(g: T) -> Self {
        let p = T::from_hex_str(
            "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e\
             65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a05\
             30cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab5\
             9494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a\
             584471bb1",
        ).unwrap(); // unwrap is ok

        let q = T::from_hex_str("f4f47f05794b256174bba6e9b396a7707e563c5b").unwrap(); // unwrap is ok

        DsaParams { p, q, g }
    }
}

pub fn compute_sha1(message: &[u8]) -> Vec<u8> {
    sha1::Sha1::digest(message).to_vec()
}

pub struct Signature<T> {
    pub r: T,
    pub s: T,
}
