#[macro_use]
extern crate error_chain;
extern crate num;
extern crate num_traits;
extern crate openssl;
extern crate rand;

use std::cmp::Ordering;
use num_traits::Num;
use num_traits::NumOps;
use num::{One, Signed, Zero};
pub use num::bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigInt, ToBigUint};
use num::pow;

pub use openssl::error;
pub use openssl::bn::{BigNum, BigNumContext, BigNumRef};

error_chain!{}

//#[derive(Eq, PartialEq, PartialOrd, Ord, Debug)]
//pub struct BigNum<T> {
//    num: T
//}

pub trait BigNumTrait: Sized + Ord + std::fmt::Debug {
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u32(u: u32) -> Self;
    fn from_bytes_be(bytes: &[u8]) -> Self;
    fn to_bytes_be(&self) -> Vec<u8>;
    fn from_hex_str(bytes: &str) -> Result<Self>;
    fn from_dec_str(bytes: &str) -> Result<Self>;
    fn to_dec_str(&self) -> String;
    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self;
    fn gen_below(bound: &Self) -> Self;
    fn gen_prime(bits: usize) -> Self;
    fn gen_random(bits: usize) -> Self;
    fn mod_math(&self, n: &Self) -> Self;
    fn invmod(&self, n: &Self) -> Option<Self>;
    fn power(&self, k: usize) -> Self;
    fn root(&self, k: usize) -> (Self, bool);
    fn clone(x: &Self) -> Self;
    fn rsh(&self, k: usize) -> Self;
    fn lsh(&self, k: usize) -> Self;
    fn bits(&self) -> usize;
    fn bytes(&self) -> usize;
}

//impl Clone for BigNum<BigNum> {
//    fn clone(&self) -> Self {
//        BigNum { num: self.num.as_ref().to_owned().unwrap() }
//    }
//}
//
//impl Clone for BigNum<BigInt> {
//    fn clone(&self) -> Self {
//        BigNum { num: self.num.clone() }
//    }
//}
//
//impl<'a1, 'a2, T> std::ops::Add<&'a2 BigNum<T>> for &'a1 BigNum<T>
//where &'a1 T: std::ops::Add<&'a2 T, Output=T> {
//    type Output = BigNum<T>;
//
//    fn add(self, other: &'a2 BigNum<T>) -> Self::Output {
//        BigNum { num: &self.num + &other.num }
//    }
//}
//
//impl<'a1, 'a2, T> std::ops::Sub<&'a2 BigNum<T>> for &'a1 BigNum<T>
//where &'a1 T: std::ops::Sub<&'a2 T, Output=T> {
//    type Output = BigNum<T>;
//
//    fn sub(self, other: &'a2 BigNum<T>) -> Self::Output {
//        BigNum { num: &self.num - &other.num }
//    }
//}
//
//impl<'a1, 'a2, T> std::ops::Mul<&'a2 BigNum<T>> for &'a1 BigNum<T>
//where &'a1 T: std::ops::Mul<&'a2 T, Output=T> {
//    type Output = BigNum<T>;
//
//    fn mul(self, other: &'a2 BigNum<T>) -> Self::Output {
//        BigNum { num: &self.num * &other.num }
//    }
//}
//
//impl<'a1, 'a2, T> std::ops::Div<&'a2 BigNum<T>> for &'a1 BigNum<T>
//where &'a1 T: std::ops::Div<&'a2 T, Output=T> {
//    type Output = BigNum<T>;
//
//    fn div(self, other: &'a2 BigNum<T>) -> Self::Output {
//        BigNum { num: &self.num / &other.num }
//    }
//}
//
//impl<'a1, 'a2, T> std::ops::Rem<&'a2 BigNum<T>> for &'a1 BigNum<T>
//where &'a1 T: std::ops::Rem<&'a2 T, Output=T> {
//    type Output = BigNum<T>;
//
//    fn rem(self, other: &'a2 BigNum<T>) -> Self::Output {
//        BigNum { num: &self.num % &other.num }
//    }
//}
//
//impl<T: BigNumTrait> BigNumTrait for BigNum<T> {
//    fn zero() -> Self {
//        BigNum { num: T::zero() }
//    }
//
//    fn one() -> Self {
//        BigNum { num: T::one() }
//    }
//
//    fn from_u32(u: u32) -> Self {
//        BigNum { num: T::from_u32(u) }
//    }
//
//    fn from_bytes_be(bytes: &[u8]) -> Self {
//        BigNum { num: T::from_bytes_be(bytes) }
//    }
//
//    fn to_bytes_be(&self) -> Vec<u8> {
//        self.num.to_bytes_be()
//    }
//
//    fn from_hex_str(bytes: &str) -> Result<Self> {
//        BigNumTrait::from_hex_str(bytes).map(|x| BigNum { num: x })
//    }
//
//    fn from_dec_str(bytes: &str) -> Result<Self> {
//        BigNumTrait::from_dec_str(bytes).map(|x| BigNum { num: x })
//    }
//
//    fn to_dec_str(&self) -> String {
//        self.num.to_dec_str()
//    }
//
//    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
//        BigNum { num: self.num.mod_exp(&exponent.num, &modulus.num) }
//    }
//
//    fn gen_below(bound: &Self) -> Self {
//        BigNum { num: T::gen_below(&bound.num) }
//    }
//
//    fn gen_prime(bits: usize) -> Self {
//        BigNum { num: T::gen_prime(bits) }
//    }
//
//    fn gen_random(bits: usize) -> Self {
//        BigNum { num: T::gen_random(bits) }
//    }
//
//    fn mod_math(&self, n: &Self) -> Self {
//        BigNum { num: self.num.mod_math(&n.num) }
//    }
//
//    fn invmod(&self, n: &Self) -> Option<Self> {
//        self.num.invmod(&n.num).map(|x| BigNum { num: x })
//    }
//
//    fn power(&self, k: usize) -> Self {
//        BigNum { num: self.num.power(k) }
//    }
//
//    fn root(&self, k: usize) -> (Self, bool) {
//        let (root, flag) = self.num.root(k);
//        (BigNum { num: root }, flag)
//    }
//
//    fn clone(x: &Self) -> Self {
//        BigNum { num: BigNumTrait::clone(&x.num) }
//    }
//
//    fn rsh(&self, k: usize) -> Self {
//        BigNum { num: self.num.rsh(k) }
//    }
//
//    fn lsh(&self, k: usize) -> Self {
//        BigNum { num: self.num.lsh(k) }
//    }
//
//    fn bits(&self) -> usize {
//        self.num.bits()
//    }
//
//    fn bytes(&self) -> usize {
//        self.num.bytes()
//    }
//}

impl BigNumTrait for BigUint {
    fn zero() -> Self {
        Zero::zero()
    }

    fn one() -> Self {
        One::one()
    }

    fn from_u32(u: u32) -> Self {
        u.to_biguint().unwrap()
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        BigUint::from_bytes_be(bytes)
    }

    fn from_hex_str(bytes: &str) -> Result<Self> {
        BigUint::from_str_radix(bytes, 16).chain_err(|| "invalid hex string")
    }

    fn from_dec_str(bytes: &str) -> Result<Self> {
        BigUint::from_str_radix(bytes, 10).chain_err(|| "invalid dec string")
    }

    fn to_dec_str(&self) -> String {
        self.to_str_radix(10)
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.to_bytes_be()
    }

    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        let (zero, one): (BigUint, BigUint) = (Zero::zero(), One::one());
        let mut result = one.clone();
        let mut base = self % modulus;
        let mut exponent = exponent.clone();

        while exponent > zero {
            // Accumulate current base if current exponent bit is 1
            if (&exponent & &one) == one {
                result = &result * &base;
                result = &result % modulus;
            }
            // Get next base by squaring
            base = &base * &base;
            base = &base % modulus;

            // Get next bit of exponent
            exponent = exponent >> 1;
        }

        result
    }

    fn gen_below(bound: &Self) -> Self {
        let mut rng = rand::thread_rng();
        rng.gen_biguint_below(bound)
    }

    fn gen_prime(bits: usize) -> Self {
        BigUint::from_bytes_be(&<BigNum as BigNumTrait>::gen_prime(bits).to_vec())
    }

    fn gen_random(bits: usize) -> Self {
        let mut rng = rand::thread_rng();
        rng.gen_biguint(bits)
    }

    fn mod_math(&self, n: &Self) -> Self {
        let mut r = self % n;
        if r < Zero::zero() {
            r = &r + n;
        }
        r
    }

    fn invmod(&self, n: &Self) -> Option<Self> {
        let (zero, one): (BigUint, BigUint) = (Zero::zero(), One::one());
        let mut l: (BigInt, BigInt) = (Zero::zero(), One::one());
        let mut r = (n.clone(), self.clone());
        while r.1 != zero {
            let q = BigInt::from_biguint(Sign::Plus, &r.0 / &r.1);
            //k = (k.1, k.0 - q*k.1);
            l = (l.1.clone(), &l.0 - &(&q * &l.1));
            r = (r.1.clone(), &r.0 % &r.1);
            //assert_eq!(k.0 * n + l.0 * x, r.0);
        }
        if r.0 == one {
            Some(l.0.mod_math(&n.to_bigint().unwrap()).to_biguint().unwrap())
        } else {
            None
        }
    }

    fn power(&self, k: usize) -> Self {
        pow(self.clone(), k)
    }

    //Returns a pair (r, is_root), where r is the biggest integer with r^k <= x, and is_root indicates
    //whether we have equality.
    fn root(&self, k: usize) -> (Self, bool) {
        let one: BigUint = One::one();
        let mut a = one.clone();
        let mut b = self.clone();
        while a <= b {
            let mid = (&a + &b) >> 1;
            let power = pow(mid.clone(), k); // TODO Do we need to clone here?
            match self.cmp(&power) {
                Ordering::Greater => a = &mid.clone() + &one,
                Ordering::Less => b = &mid.clone() - &one,
                Ordering::Equal => return (mid, true),
            }
        }
        (b, false)
    }

    fn clone(n: &Self) -> Self {
        n.clone()
    }

    fn rsh(&self, k: usize) -> Self {
        self >> k
    }

    fn lsh(&self, k: usize) -> Self {
        self << k
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn bytes(&self) -> usize {
        let bits = self.bits();
        let mut result = bits / 8;
        if bits % 8 != 0 {
            result += 1;
        }
        result
    }
}

impl BigNumTrait for BigInt {
    fn zero() -> Self {
        Zero::zero()
    }

    fn one() -> Self {
        One::one()
    }

    fn from_u32(u: u32) -> Self {
        u.to_bigint().unwrap()
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        BigInt::from_bytes_be(Sign::Plus, bytes)
    }

    fn from_hex_str(bytes: &str) -> Result<Self> {
        BigInt::from_str_radix(bytes, 16).chain_err(|| "invalid hex string")
    }

    fn from_dec_str(bytes: &str) -> Result<Self> {
        BigInt::from_str_radix(bytes, 10).chain_err(|| "invalid dec string")
    }

    fn to_dec_str(&self) -> String {
        self.to_str_radix(10)
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        assert!(self.is_positive());
        self.to_bytes_be().1
    }

    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
        let two = &one + &one;
        let mut result = one.clone();
        let mut base = self % modulus;
        let mut exponent = exponent.clone();

        while exponent > zero {
            if (&exponent % &two) == one {
                result = &(&result * &base) % modulus;
            }

            base = &(&base * &base) % modulus;
            exponent = exponent >> 1;
        }

        result
    }

    fn gen_below(bound: &Self) -> Self {
        let mut rng = rand::thread_rng();
        rng.gen_bigint_range(&Zero::zero(), bound)
    }

    fn gen_prime(bits: usize) -> Self {
        BigInt::from_biguint(Sign::Plus, BigUint::gen_prime(bits))
    }

    fn gen_random(bits: usize) -> Self {
        // BigInt::gen_bigint can probably return negative values!?
        BigInt::from_biguint(Sign::Plus, BigUint::gen_random(bits))
    }

    fn mod_math(&self, n: &Self) -> Self {
        let mut r = self % n;
        if r.is_negative() {
            r = &r + n;
        }
        r
    }

    fn invmod(&self, n: &Self) -> Option<Self> {
        let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
        let mut l: (BigInt, BigInt) = (Zero::zero(), One::one());
        let mut r = (n.clone(), self.clone());
        while r.1 != zero {
            let q = &r.0 / &r.1;
            //k = (k.1, k.0 - q*k.1);
            l = (l.1.clone(), &l.0 - &(&q * &l.1));
            r = (r.1.clone(), &r.0 % &r.1);
            //assert_eq!(k.0 * n + l.0 * x, r.0);
        }
        if r.0 == one {
            Some(l.0.mod_math(n))
        } else {
            None
        }
    }

    fn power(&self, k: usize) -> Self {
        pow(self.clone(), k)
    }

    //Returns a pair (r, is_root), where r is the biggest integer with r^k <= x, and is_root indicates
    //whether we have equality.
    fn root(&self, k: usize) -> (Self, bool) {
        let one: BigInt = One::one();
        let mut a = one.clone();
        let mut b = self.clone();
        while a <= b {
            let mid = (&a + &b) >> 1;
            let power = pow(mid.clone(), k); // TODO Do we need to clone here?
            match self.cmp(&power) {
                Ordering::Greater => a = &mid.clone() + &one,
                Ordering::Less => b = &mid.clone() - &one,
                Ordering::Equal => return (mid, true),
            }
        }
        (b, false)
    }

    fn clone(n: &Self) -> Self {
        n.clone()
    }

    fn rsh(&self, k: usize) -> Self {
        self >> k
    }

    fn lsh(&self, k: usize) -> Self {
        self << k
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn bytes(&self) -> usize {
        let bits = self.bits();
        let mut result = bits / 8;
        if bits % 8 != 0 {
            result += 1;
        }
        result
    }
}

impl BigNumTrait for BigNum {
    fn zero() -> Self {
        BigNumTrait::from_u32(0)
    }

    fn one() -> Self {
        BigNumTrait::from_u32(1)
    }

    fn from_u32(u: u32) -> Self {
        BigNum::from_u32(u).unwrap()
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        BigNum::from_slice(bytes).unwrap()
    }

    fn from_hex_str(bytes: &str) -> Result<Self> {
        BigNum::from_hex_str(bytes).chain_err(|| "invalid hex string")
    }

    fn from_dec_str(bytes: &str) -> Result<Self> {
        BigNum::from_dec_str(bytes).chain_err(|| "invalid dec string")
    }

    fn to_dec_str(&self) -> String {
        BigNumRef::to_dec_str(&self).unwrap().to_string()
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.to_vec()
    }

    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        let mut result = BigNum::new().unwrap();
        BigNumRef::mod_exp(
            &mut result,
            self,
            exponent,
            modulus,
            &mut BigNumContext::new().unwrap(),
        ).unwrap();
        result
    }

    fn gen_below(bound: &Self) -> Self {
        let mut result = BigNum::new().unwrap();
        BigNumRef::rand_range(bound, &mut result).unwrap();
        result
    }

    fn gen_prime(bits: usize) -> Self {
        let mut result = BigNum::new().unwrap();
        result
            .generate_prime(bits as i32, true, None, None)
            .unwrap();
        result
    }

    fn gen_random(bits: usize) -> BigNum {
        let mut result = BigNum::new().unwrap();
        result
            .pseudo_rand(bits as i32, openssl::bn::MSB_MAYBE_ZERO, false)
            .unwrap();
        result
    }

    fn mod_math(&self, n: &Self) -> Self {
        let mut r = self % n;
        if r < Self::zero() {
            r = &r + n;
        }
        r
    }

    fn invmod(&self, n: &Self) -> Option<Self> {
        //let mut k = (1, 0);
        let mut l = (Self::zero(), Self::one());
        let mut r = (Self::clone(n), Self::clone(self));
        while r.1 != Self::zero() {
            let q = &r.0 / &r.1;
            //k = (k.1, k.0 - q*k.1);
            l = (Self::clone(&l.1), &l.0 - &(&q * &l.1));
            r = (Self::clone(&r.1), &r.0 % &r.1);
            //assert_eq!(k.0 * n + l.0 * self, r.0);
        }
        if r.0 == Self::one() {
            Some(l.0.mod_math(n))
        } else {
            None
        }
    }

    fn power(&self, k: usize) -> Self {
        let mut result = BigNum::new().unwrap();
        result
            .exp(
                self,
                &<Self as BigNumTrait>::from_u32(k as u32),
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        result
    }

    //Returns a pair (r, is_root), where r is the biggest integer with r^k <= x, and is_root indicates
    //whether we have equality.
    fn root(&self, k: usize) -> (Self, bool) {
        let one = Self::one();
        let mut a = Self::clone(&one);
        let mut b = Self::clone(self);
        let mut mid = BigNum::new().unwrap();
        let mut power = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        while a <= b {
            mid.rshift1(&(&a + &b)).unwrap();
            power
                .exp(&mid, &<Self as BigNumTrait>::from_u32(k as u32), &mut ctx)
                .unwrap();
            match self.cmp(&power) {
                Ordering::Greater => a = &Self::clone(&mid) + &one,
                Ordering::Less => b = &Self::clone(&mid) - &one,
                Ordering::Equal => return (mid, true),
            }
        }
        (b, false)
    }

    fn clone(n: &Self) -> Self {
        n.as_ref().to_owned().unwrap()
    }

    fn rsh(&self, k: usize) -> Self {
        let mut result = BigNum::new().unwrap();
        result.rshift(self, k as i32).unwrap();
        result
    }

    fn lsh(&self, k: usize) -> Self {
        let mut result = BigNum::new().unwrap();
        result.lshift(self, k as i32).unwrap();
        result
    }

    fn bits(&self) -> usize {
        self.num_bits() as usize
    }

    fn bytes(&self) -> usize {
        self.num_bytes() as usize
    }
}

pub trait BigNumExt: Sized {
    fn ceil_div(&self, k: &Self) -> (Self, Self);
    fn floor_div(&self, k: &Self) -> (Self, Self);
}

impl<T: BigNumTrait> BigNumExt for T
where
    for<'a1, 'a2> &'a1 T: NumOps<&'a2 T, T>,
{
    fn ceil_div(&self, k: &T) -> (T, T) {
        let q = &(&(self + &k) - &T::one()) / &k;
        let r = &(&q * k) - self;
        (q, r)
    }

    fn floor_div(&self, k: &T) -> (T, T) {
        (self / k, self % k)
    }
}
