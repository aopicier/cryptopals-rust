extern crate bignum;
extern crate num_traits;
extern crate rsa;

use num_traits::NumOps;

pub struct DsaPublic<'a, T: 'a> {
    pub params: &'a DsaParams<T>,
    pub y: T,
}

impl<'a, T> DsaPublic<'a, T>
where
    T: bignum::BigNumTrait+bignum::BigNumExt,
    for<'a1, 'a2> &'a1 T: NumOps<&'a2 T, T>,
{
    pub fn generate(private: &'a DsaPrivate<T>) -> Self {
        let params = private.params;
        let y = params.g.mod_exp(&private.x, &params.p);
        DsaPublic {
            params: params,
            y: y,
        }
    }

    pub fn secret_key_from_k(&self, m: &T, &Signature { ref r, ref s }: &Signature<T>, k: &T) -> T {
        let q = &self.params.q;
        let x = &(&(s * k) - m) * &r.invmod(q).unwrap();
        x.mod_math(q)
    }

    pub fn secret_key_from_two_signatures_with_same_k(
        &self,
        m1: &T,
        s1: &Signature<T>,
        m2: &T,
        s2: &Signature<T>,
    ) -> T {
        assert_eq!(s1.r, s2.r);
        let q = &self.params.q;
        let k = &(m1 - m2).mod_math(q) * &T::invmod(&T::mod_math(&(&s1.s - &s2.s), q), q).unwrap();
        self.secret_key_from_k(m1, s1, &k)
    }

    pub fn verify_signature(&self, m: &T, &Signature { ref r, ref s }: &Signature<T>) -> bool {
        let zero = T::zero();
        let p = &self.params.p;
        let q = &self.params.q;
        let g = &self.params.g;
        if r <= &zero || r >= q || s <= &zero || s >= q {
            return false;
        }
        let w = T::invmod(s, q).unwrap();
        let u1 = T::mod_math(&(m * &w), q);
        let u2 = T::mod_math(&(r * &w), q);
        let v1 = g.mod_exp(&u1, p);
        let v2 = self.y.mod_exp(&u2, p);
        let v = T::mod_math(&T::mod_math(&(&v1 * &v2), p), q);
        &v == r
    }
}

pub struct DsaPrivate<'a, T: 'a> {
    pub params: &'a DsaParams<T>,
    pub x: T,
}

impl<'a, T> DsaPrivate<'a, T>
where
    T: bignum::BigNumTrait+bignum::BigNumExt,
    for<'a1, 'a2> &'a1 T: NumOps<&'a2 T, T>,
{
    pub fn generate(params: &'a DsaParams<T>) -> Self {
        let x = rand_range_safe(&params.q);
        DsaPrivate {
            params: params,
            x: x,
        }
    }

    pub fn sign(&self, m: &T) -> (Signature<T>, T) {
        let zero = T::zero();
        let one = T::one();
        let p = &self.params.p;
        let q = &self.params.q;
        let g = &self.params.g;

        let mut k: T;
        let mut r: T;
        let mut s: T;
        loop {
            k = T::gen_below(q);
            if k == zero || k == one {
                continue;
            }
            r = g.mod_exp(&k, p);
            r = r.mod_math(q);
            if r == zero {
                continue;
            }
            s = &k.invmod(q).unwrap() * &(m + &(&r * &self.x));
            s = s.mod_math(q);
            if s == zero {
                continue;
            }
            break;
        }
        (Signature { r: r, s: s }, k)
    }
}

pub fn rand_range_safe<T: bignum::BigNumTrait>(q: &T) -> T {
    let zero = T::zero();
    let one = T::one();
    let mut x = T::clone(&zero);
    while x == zero || x == one {
        x = T::gen_below(q);
    }
    x
}

pub fn fake_signature<T>(public: &DsaPublic<T>) -> Signature<T>
where
    T: bignum::BigNumTrait+bignum::BigNumExt,
    for<'b> &'b T: NumOps<&'b T, T>,
{
    let p = &public.params.p;
    let q = &public.params.q;
    let z = rand_range_safe(q);
    let mut r = T::mod_exp(&public.y, &z, p);
    r = T::mod_math(&r, q);
    let mut s = &r * &T::invmod(&z, q).unwrap();
    s = T::mod_math(&s, q);
    Signature { r: r, s: s }
}

pub struct DsaParams<T> {
    pub p: T,
    pub q: T,
    pub g: T,
}

impl<T: bignum::BigNumTrait> DsaParams<T> {
    pub fn generate() -> Self {
        let p = T::from_hex_str(
            "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"
            ).unwrap();
        let q = T::from_hex_str("f4f47f05794b256174bba6e9b396a7707e563c5b").unwrap();
        let g = T::from_hex_str("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291").unwrap();
        DsaParams { p: p, q: q, g: g }
    }
}

pub struct Signature<T> {
    pub r: T,
    pub s: T,
}
