#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::many_single_char_names)
)]

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
    pub fn generate(mut bits: usize) -> Self {
        // Make sure that p and q are bigger than 7.
        if bits <= 3 {
            bits = 4;
        }

        // TODO Should not use the same size for p and q
        let p = T::gen_safe_prime(bits);
        let q = T::gen_safe_prime(bits);
        let n = &p * &q;
        let one = T::one();
        let pn = &p - &one;
        let qn = &q - &one;
        let et = &pn * &qn;
        let e = T::from_u32(3);

        // We know that et is not divisible by 3 because
        // p and q are safe primes bigger than 7. (For a safe prime p
        // bigger than 7, (p - 1)/2 is a prime bigger than 3. Therefore
        // p - 1 is not divisible by 3.)
        let d = e.invmod(&et).expect("primes were not safe");

        Rsa { n, d, e }
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
