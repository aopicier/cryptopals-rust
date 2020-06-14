use crate::errors::*;

use rsa::Rsa;

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

use rand::Rng;

use std::cmp;

struct Server {
    rsa: Rsa<BigNum>,
}

// We do not need an oracle which checks for full PKCS#1v1.5 conformance.
// It suffices that the oracle tells us whether the cleartext is of the form
// 00 || 02 || another k - 2 bytes,
// where k is the number of bytes in the RSA modulus.
impl Server {
    fn new(rsa_bits: usize) -> Self {
        let rsa = Rsa::generate(rsa_bits);
        Server { rsa }
    }

    fn n(&self) -> &BigNum {
        self.rsa.n()
    }

    fn oracle(&self, ciphertext: &BigNum) -> bool {
        let cleartext = self.rsa.decrypt(ciphertext);
        cleartext.rsh(8 * (self.rsa.n().bytes() - 2)) == BigNum::from_u32(2)
    }

    fn get_ciphertext(&self) -> BigNum {
        let k = self.rsa.n().bytes() as usize;
        let cleartext = b"kick it, CC";
        let cleartext_len = cleartext.len();
        assert!(cleartext_len <= k - 11);
        let mut padded_cleartext = vec![2u8];
        let mut rng = rand::thread_rng();
        padded_cleartext.extend((0..(k - 3 - cleartext_len)).map(|_| rng.gen_range(1, 256) as u8));
        padded_cleartext.push(0);
        padded_cleartext.extend_from_slice(cleartext);
        let m: BigNum = BigNumTrait::from_bytes_be(&padded_cleartext);
        self.rsa.encrypt(&m)
    }

    fn encrypt(&self, cleartext: &BigNum) -> BigNum {
        self.rsa.encrypt(cleartext)
    }
}

// We use the variable names from the paper
#[allow(non_snake_case)]
#[allow(clippy::just_underscores_and_digits)]
#[allow(clippy::many_single_char_names)]
pub fn run(rsa_bits: usize) -> Result<()> {
    let _0 = BigNum::zero();
    let _1 = BigNum::one();
    let _2 = BigNum::from_u32(2);
    let _3 = BigNum::from_u32(3);

    let server = Server::new(rsa_bits);
    let n = server.n();
    let k = n.bytes() as usize;
    let B = _1.lsh(8 * (k - 2));
    let _2B = &_2 * &B;
    let _3B = &_3 * &B;

    let c = server.get_ciphertext();

    // We are only ever going to use `oracle` in the following way
    let wrapped_oracle = |s: &BigNum| -> bool { server.oracle(&(&c * &server.encrypt(s))) };

    let mut M_prev = vec![(_2B.clone(), &_3B - &_1)];
    let mut s_prev = _1.clone();
    let mut i = 1;

    // We know that the cleartext corresponding to our ciphertext is PKCS conforming, so we can skip
    // Step 1 of the paper.
    loop {
        // Step 2
        let mut si;
        if i == 1 {
            // Step 2.a
            si = n.ceil_quotient(&_3B);
            while !wrapped_oracle(&si) {
                si = &si + &_1;
            }
        } else if M_prev.len() >= 2 {
            // Step 2.b
            si = &s_prev + &_1;
            while !wrapped_oracle(&si) {
                si = &si + &_1;
            }
        } else {
            // Step 2.c
            let (ref a, ref b) = M_prev[0];
            let mut ri = (&_2 * &(&(b * &s_prev) - &_2B)).ceil_quotient(n);
            'outer: loop {
                si = (&_2B + &(&ri * n)).ceil_quotient(b);
                let U = (&_3B + &(&ri * n)).ceil_quotient(a);
                while si < U {
                    if wrapped_oracle(&si) {
                        break 'outer;
                    }
                    si = &si + &_1;
                }
                ri = &ri + &_1;
            }
        }

        let mut Mi = Vec::new();
        for &(ref a, ref b) in &M_prev {
            let mut r = (&(&(a * &si) - &_3B) + &_1).ceil_quotient(n);
            let U = (&(b * &si) - &_2B).floor_quotient(n);
            while r <= U {
                Mi.push((
                    cmp::max(a.clone(), (&_2B + &(&r * n)).ceil_quotient(&si)),
                    cmp::min(b.clone(), (&(&_3B - &_1) + &(&r * n)).floor_quotient(&si)),
                ));
                r = &r + &_1;
            }
        }

        Mi.sort();
        Mi.dedup();
        if Mi.len() == 1 && Mi[0].0 == Mi[0].1 {
            // Verify that our cleartext encrypts to the ciphertext
            return compare_eq(&c, &server.encrypt(&Mi[0].0));
        }
        i += 1;
        s_prev = si;
        M_prev = Mi;
    }
}
