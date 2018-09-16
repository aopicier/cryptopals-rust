#![cfg_attr(feature = "cargo-clippy", allow(clippy::new_without_default))]

extern crate rand;
extern crate serialize;

use communication::Communicate;

use bignum::BigNumTrait;
pub use bignum::NumBigInt as BigNum;
use failure::Error;
use mac::hmac_sha256;
use sha2::{Digest, Sha256};

use rand::Rng;

pub enum LoginResult {
    Success,
    Failure,
}

#[derive(Debug)]
pub struct SRP {
    N: BigNum,
    g: BigNum,
    k: BigNum,
}

pub fn serialize<T: BigNumTrait>(x: &T) -> Vec<u8> {
    x.to_bytes_be()
}

pub fn deserialize<T: BigNumTrait>(x: &[u8]) -> T {
    T::from_bytes_be(x)
}

impl SRP {
    pub fn new() -> Self {
        Self::new_with_k(3)
    }

    pub fn new_with_k(k: u32) -> Self {
        let N_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
                     020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
                     4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
                     ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
                     98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
                     9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";

        let N = BigNum::from_hex_str(N_hex).unwrap();
        let g = BigNum::from_u32(2);
        SRP {
            N,
            g,
            k: BigNum::from_u32(k),
        }
    }

    pub fn password_to_verifier(&self, password: &[u8]) -> (Vec<u8>, BigNum) {
        let mut rng = rand::thread_rng();
        // Which size should the salt have?
        let salt: Vec<u8> = rng.gen_iter::<u8>().take(128).collect();

        let x = compute_x(&salt, password);
        (salt, self.g.mod_exp(&x, &self.N))
    }

    pub fn g(&self) -> &BigNum {
        &self.g
    }

    pub fn N(&self) -> &BigNum {
        &self.N
    }
}

struct HandshakeState<'a> {
    srp: &'a SRP,
    exponent: BigNum,
    power: BigNum,
}

impl<'a> HandshakeState<'a> {
    pub fn new(srp: &'a SRP) -> Self {
        let exponent = BigNum::gen_below(&srp.N);
        let power = srp.g.mod_exp(&exponent, &srp.N);
        HandshakeState {
            srp,
            exponent,
            power,
        }
    }
}

pub struct ClientHandshake<'a> {
    state: HandshakeState<'a>,
}

impl<'a> ClientHandshake<'a> {
    pub fn new(srp: &'a SRP) -> Self {
        ClientHandshake {
            state: HandshakeState::new(srp),
        }
    }

    pub fn A(&self) -> &BigNum {
        &self.state.power
    }

    pub fn compute_hashed_secret(
        &self,
        B: &BigNum,
        u: &BigNum,
        salt: &[u8],
        password: &[u8],
    ) -> Vec<u8> {
        let state = &self.state;
        let srp = state.srp;
        let N = &srp.N;
        let g = &srp.g;
        let k = &srp.k;
        let a = &state.exponent;

        let x = compute_x(salt, password);
        let S = (B - &(k * &g.mod_exp(&x, N))).mod_exp(&(a + &(u * &x)), N);
        hash_secret(&S, salt)
    }
}

pub struct ServerHandshake<'a> {
    state: HandshakeState<'a>,
    B: BigNum,
    salt: &'a [u8],
    v: &'a BigNum,
}

impl<'a> ServerHandshake<'a> {
    pub fn new(srp: &'a SRP, salt: &'a [u8], v: &'a BigNum) -> Self {
        let state = HandshakeState::new(srp);
        let B = &state.power + &(&srp.k * v);
        ServerHandshake { state, B, salt, v }
    }

    pub fn B(&self) -> &BigNum {
        &self.B
    }

    pub fn compute_hashed_secret(&self, A: &BigNum, u: &BigNum) -> Vec<u8> {
        let state = &self.state;
        let srp = state.srp;
        let N = &srp.N;
        let b = &state.exponent;

        let S = (A * &self.v.mod_exp(u, N)).mod_exp(b, N);
        hash_secret(&S, self.salt)
    }
}

pub trait UComputer {
    fn compute_u<T: Communicate>(&BigNum, &BigNum, &mut T) -> Result<BigNum, Error>;
}

pub struct DefaultUComputer;

impl UComputer for DefaultUComputer {
    fn compute_u<T: Communicate>(A: &BigNum, B: &BigNum, _: &mut T) -> Result<BigNum, Error> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&serialize(A));
        buffer.extend_from_slice(&serialize(B));
        Ok(deserialize(&Sha256::digest(&buffer)))
    }
}

pub fn compute_x(salt: &[u8], password: &[u8]) -> BigNum {
    let mut buffer = Vec::with_capacity(salt.len() + password.len());
    buffer.extend_from_slice(salt);
    buffer.extend_from_slice(password);
    deserialize(&Sha256::digest(&buffer))
}

pub fn hash_secret(S: &BigNum, salt: &[u8]) -> Vec<u8> {
    let K = Sha256::digest(&serialize(S)).to_vec();
    hmac_sha256(&K, salt)
}

pub fn zero() -> BigNum {
    BigNum::zero()
}
