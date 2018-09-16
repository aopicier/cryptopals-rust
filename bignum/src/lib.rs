extern crate failure;
extern crate num;
extern crate num_traits;
extern crate openssl;
extern crate rand;

use failure::{Error, ResultExt};
use num::bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use num::pow;
use num::{One, Signed, Zero};
use num_traits::Num;
use num_traits::NumOps;
use std::cmp::Ordering;

use openssl::bn::{BigNum, BigNumContext, BigNumRef};
pub use openssl::error;

pub type OpensslBigNum = BigNumWrapper<BigNum>;
pub type NumBigInt = BigNumWrapper<BigInt>;

#[derive(Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct BigNumWrapper<T> {
    num: T,
}

pub trait BigNumTrait: Sized + Ord + std::fmt::Debug {
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u32(u: u32) -> Self;
    fn from_bytes_be(bytes: &[u8]) -> Self;
    fn to_bytes_be(&self) -> Vec<u8>;
    fn from_hex_str(bytes: &str) -> Result<Self, Error>;
    fn from_dec_str(bytes: &str) -> Result<Self, Error>;
    fn to_dec_str(&self) -> String;
    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self;
    fn gen_below(bound: &Self) -> Self;
    fn gen_safe_prime(bits: usize) -> Self;
    fn gen_random(bits: usize) -> Self;
    fn invmod(&self, n: &Self) -> Option<Self>;
    fn power(&self, k: usize) -> Self;
    fn clone(x: &Self) -> Self;
    fn rsh(&self, k: usize) -> Self;
    fn lsh(&self, k: usize) -> Self;
    fn bits(&self) -> usize;
    fn bytes(&self) -> usize;
}

impl Clone for BigNumWrapper<BigNum> {
    fn clone(&self) -> Self {
        BigNumWrapper {
            num: self.num.as_ref().to_owned().unwrap(),
        }
    }
}

impl Clone for BigNumWrapper<BigInt> {
    fn clone(&self) -> Self {
        BigNumWrapper {
            num: self.num.clone(),
        }
    }
}

/* Unfortunately the following generic impls tend to lead to
 * infinite recursions in the type system. We therefore use a
 * macro to spell out the impls for all the types we are
 * interested in.

 * See also
 * https://users.rust-lang.org/t/arithmetic-operators-on-references-and-trait-constraints/13158 */

/*
impl<'a1, 'a2, T> std::ops::Add<&'a2 BigNumWrapper<T>> for &'a1 BigNumWrapper<T>
where &'a1 T: std::ops::Add<&'a2 T, Output=T> {
    type Output = BigNumWrapper<T>;

    fn add(self, other: &'a2 BigNumWrapper<T>) -> Self::Output {
        BigNumWrapper { num: &self.num + &other.num }
    }
}

impl<'a1, 'a2, T> std::ops::Sub<&'a2 BigNumWrapper<T>> for &'a1 BigNumWrapper<T>
where &'a1 T: std::ops::Sub<&'a2 T, Output=T> {
    type Output = BigNumWrapper<T>;

    fn sub(self, other: &'a2 BigNumWrapper<T>) -> Self::Output {
        BigNumWrapper { num: &self.num - &other.num }
    }
}

impl<'a1, 'a2, T> std::ops::Mul<&'a2 BigNumWrapper<T>> for &'a1 BigNumWrapper<T>
where &'a1 T: std::ops::Mul<&'a2 T, Output=T> {
    type Output = BigNumWrapper<T>;

    fn mul(self, other: &'a2 BigNumWrapper<T>) -> Self::Output {
        BigNumWrapper { num: &self.num * &other.num }
    }
}

impl<'a1, 'a2, T> std::ops::Div<&'a2 BigNumWrapper<T>> for &'a1 BigNumWrapper<T>
where &'a1 T: std::ops::Div<&'a2 T, Output=T> {
    type Output = BigNumWrapper<T>;

    fn div(self, other: &'a2 BigNumWrapper<T>) -> Self::Output {
        BigNumWrapper { num: &self.num / &other.num }
    }
}

impl<'a1, 'a2, T> std::ops::Rem<&'a2 BigNumWrapper<T>> for &'a1 BigNumWrapper<T>
where &'a1 T: std::ops::Rem<&'a2 T, Output=T> {
    type Output = BigNumWrapper<T>;

    fn rem(self, other: &'a2 BigNumWrapper<T>) -> Self::Output {
        BigNumWrapper { num: &self.num % &other.num }
    }
}
*/

macro_rules! impl_numops {
    ($T:ty) => {
        impl<'a1, 'a2> std::ops::Add<&'a2 BigNumWrapper<$T>> for &'a1 BigNumWrapper<$T> {
            type Output = BigNumWrapper<$T>;

            fn add(self, other: &'a2 BigNumWrapper<$T>) -> Self::Output {
                BigNumWrapper {
                    num: &self.num + &other.num,
                }
            }
        }

        impl<'a1, 'a2> std::ops::Sub<&'a2 BigNumWrapper<$T>> for &'a1 BigNumWrapper<$T> {
            type Output = BigNumWrapper<$T>;

            fn sub(self, other: &'a2 BigNumWrapper<$T>) -> Self::Output {
                BigNumWrapper {
                    num: &self.num - &other.num,
                }
            }
        }

        impl<'a1, 'a2> std::ops::Mul<&'a2 BigNumWrapper<$T>> for &'a1 BigNumWrapper<$T> {
            type Output = BigNumWrapper<$T>;

            fn mul(self, other: &'a2 BigNumWrapper<$T>) -> Self::Output {
                BigNumWrapper {
                    num: &self.num * &other.num,
                }
            }
        }

        impl<'a1, 'a2> std::ops::Div<&'a2 BigNumWrapper<$T>> for &'a1 BigNumWrapper<$T> {
            type Output = BigNumWrapper<$T>;

            fn div(self, other: &'a2 BigNumWrapper<$T>) -> Self::Output {
                BigNumWrapper {
                    num: &self.num / &other.num,
                }
            }
        }

        impl<'a1, 'a2> std::ops::Rem<&'a2 BigNumWrapper<$T>> for &'a1 BigNumWrapper<$T> {
            type Output = BigNumWrapper<$T>;

            fn rem(self, other: &'a2 BigNumWrapper<$T>) -> Self::Output {
                BigNumWrapper {
                    num: &self.num % &other.num,
                }
            }
        }
    };
}

impl_numops!(BigInt);
impl_numops!(BigNum);

impl<T: BigNumTrait> BigNumTrait for BigNumWrapper<T> {
    fn zero() -> Self {
        BigNumWrapper { num: T::zero() }
    }

    fn one() -> Self {
        BigNumWrapper { num: T::one() }
    }

    fn from_u32(u: u32) -> Self {
        BigNumWrapper {
            num: T::from_u32(u),
        }
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        BigNumWrapper {
            num: T::from_bytes_be(bytes),
        }
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.num.to_bytes_be()
    }

    fn from_hex_str(bytes: &str) -> Result<Self, Error> {
        BigNumTrait::from_hex_str(bytes).map(|x| BigNumWrapper { num: x })
    }

    fn from_dec_str(bytes: &str) -> Result<Self, Error> {
        BigNumTrait::from_dec_str(bytes).map(|x| BigNumWrapper { num: x })
    }

    fn to_dec_str(&self) -> String {
        self.num.to_dec_str()
    }

    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        BigNumWrapper {
            num: self.num.mod_exp(&exponent.num, &modulus.num),
        }
    }

    fn gen_below(bound: &Self) -> Self {
        BigNumWrapper {
            num: T::gen_below(&bound.num),
        }
    }

    fn gen_safe_prime(bits: usize) -> Self {
        BigNumWrapper {
            num: T::gen_safe_prime(bits),
        }
    }

    fn gen_random(bits: usize) -> Self {
        BigNumWrapper {
            num: T::gen_random(bits),
        }
    }

    fn invmod(&self, n: &Self) -> Option<Self> {
        self.num.invmod(&n.num).map(|x| BigNumWrapper { num: x })
    }

    fn power(&self, k: usize) -> Self {
        BigNumWrapper {
            num: self.num.power(k),
        }
    }

    fn clone(x: &Self) -> Self {
        BigNumWrapper {
            num: BigNumTrait::clone(&x.num),
        }
    }

    fn rsh(&self, k: usize) -> Self {
        BigNumWrapper {
            num: self.num.rsh(k),
        }
    }

    fn lsh(&self, k: usize) -> Self {
        BigNumWrapper {
            num: self.num.lsh(k),
        }
    }

    fn bits(&self) -> usize {
        self.num.bits()
    }

    fn bytes(&self) -> usize {
        self.num.bytes()
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

    fn from_hex_str(bytes: &str) -> Result<Self, Error> {
        BigInt::from_str_radix(bytes, 16)
            .context("invalid hex string")
            .map_err(|err| err.into())
    }

    fn from_dec_str(bytes: &str) -> Result<Self, Error> {
        BigInt::from_str_radix(bytes, 10)
            .context("invalid dec string")
            .map_err(|err| err.into())
    }

    fn to_dec_str(&self) -> String {
        self.to_str_radix(10)
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        assert!(!self.is_negative());
        self.to_bytes_be().1
    }

    fn mod_exp(&self, exponent: &Self, modulus: &Self) -> Self {
        let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
        let two = &one + &one;
        let mut result = one.clone();
        let mut base = self.remainder(&modulus);
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

    fn gen_safe_prime(bits: usize) -> Self {
        BigInt::from_bytes_be(
            Sign::Plus,
            &<BigNum as BigNumTrait>::gen_safe_prime(bits).to_vec(),
        )
    }

    fn gen_random(bits: usize) -> Self {
        let mut rng = rand::thread_rng();
        rng.gen_bigint(bits).abs()
    }

    fn invmod(&self, n: &Self) -> Option<Self> {
        let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
        let mut l: (BigInt, BigInt) = (Zero::zero(), One::one());
        let mut r = (n.clone(), self.clone());
        while r.1 != zero {
            let q = &r.0 / &r.1;
            l = (l.1.clone(), &l.0 - &(&q * &l.1));
            r = (r.1.clone(), &r.0 % &r.1);
        }
        if r.0 == one {
            Some(l.0.remainder(n))
        } else {
            None
        }
    }

    fn power(&self, k: usize) -> Self {
        pow(self.clone(), k)
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

    fn from_hex_str(bytes: &str) -> Result<Self, Error> {
        BigNum::from_hex_str(bytes)
            .context("invalid hex string")
            .map_err(|err| err.into())
    }

    fn from_dec_str(bytes: &str) -> Result<Self, Error> {
        BigNum::from_dec_str(bytes)
            .context("invalid dec string")
            .map_err(|err| err.into())
    }

    fn to_dec_str(&self) -> String {
        BigNumRef::to_dec_str(self).unwrap().to_string()
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        assert!(!self.is_negative());
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

    fn gen_safe_prime(bits: usize) -> Self {
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

    fn invmod(&self, n: &Self) -> Option<Self> {
        let mut result = BigNum::new().unwrap();

        if result
            .mod_inverse(&self, n, &mut BigNumContext::new().unwrap())
            .is_ok()
        {
            Some(result)
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
            ).unwrap();
        result
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
    // Returns the ceil of the quotient self/k.
    fn ceil_quotient(&self, k: &Self) -> Self;

    // Returns the floor of the quotient self/k.
    fn floor_quotient(&self, k: &Self) -> Self;

    // Returns the mathematical remainder of self divided by k.
    fn remainder(&self, n: &Self) -> Self;

    /* Returns a pair (r, is_root), where
     * - r is the biggest integer with r^k <= self, and
     * - is_root indicates whether we have equality. */
    fn root(&self, k: usize) -> (Self, bool);
}

impl<T: BigNumTrait> BigNumExt for T
where
    for<'a1, 'a2> &'a1 T: NumOps<&'a2 T, T>,
{
    fn ceil_quotient(&self, k: &Self) -> Self {
        assert!(*k > Self::zero());
        &(&(self + k) - &Self::one()) / k
    }

    fn floor_quotient(&self, k: &Self) -> Self {
        assert!(*k > Self::zero());
        self / k
    }

    fn remainder(&self, k: &Self) -> Self {
        assert!(*k > Self::zero());

        let mut r = self % k;
        if r < Self::zero() {
            r = &r + k;
        }
        r
    }

    fn root(&self, k: usize) -> (Self, bool) {
        assert!(*self > Self::zero(), "base is not positive");
        assert!(k > 0, "exponent is not positive");

        let one = Self::one();
        let mut a = Self::clone(&one);
        let mut b = Self::clone(&self);
        while a <= b {
            let mid = (&a + &b).rsh(1);
            let power = mid.power(k);
            match self.cmp(&power) {
                Ordering::Greater => a = &mid + &one,
                Ordering::Less => b = &mid - &one,
                Ordering::Equal => return (mid, true),
            }
        }
        (b, false)
    }
}
