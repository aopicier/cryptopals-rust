extern crate bignum;
extern crate num_traits;
use num_traits::NumOps;

pub struct Rsa<T> {
    n: T,
    d: T,
    e: T,
}

impl<T: bignum::BigNumTrait> Rsa<T>
where
    for<'a1, 'a2> &'a1 T: NumOps<&'a2 T, T>,
{
    pub fn generate(bits: usize) -> Self {
        let p = T::gen_prime(bits);
        let q = T::gen_prime(bits);
        let n = &p * &q;
        let one = T::one();
        let pn = &p - &one;
        let qn = &q - &one;
        let et = &pn * &qn;
        let e = T::from_u32(3);
        let d = e.invmod(&et).unwrap(); // Only works if e does not divide et
        Rsa { n: n, d: d, e: e }
    }

    pub fn encrypt(&self, m: &T) -> T {
        m.mod_exp(&self.e, &self.n)
    }

    pub fn decrypt(&self, c: &T) -> T {
        c.mod_exp(&self.d, &self.n)
    }

    pub fn n(&self) -> &T {
        &self.n
    }
}
