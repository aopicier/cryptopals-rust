#![allow(clippy::just_underscores_and_digits)]

use crate::algo::{deserialize, secret_to_key, serialize};

use crate::communication::Communicate;

use bignum::BigNumTrait;
use bignum::NumBigInt as BigNum;

use crate::handshake::{ClientDeterminesParameters, ClientServerPair, ServerCanOverrideParameters};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub trait MitmHandshake<T: Communicate> {
    fn handshake(client_stream: &mut T, server_stream: &mut T) -> Result<Vec<u8>>;
}

pub trait MitmForClientServer<T: Communicate> {
    type Mitm: MitmHandshake<T>;
    type CS: ClientServerPair<T>;
}

// Mitm used for challenge 34

pub struct MitmHandshakeFakePublicKey;

impl<T: Communicate> MitmHandshake<T> for MitmHandshakeFakePublicKey {
    fn handshake(client_stream: &mut T, server_stream: &mut T) -> Result<Vec<u8>> {
        let p = client_stream
            .receive()?
            .ok_or_else(|| "did not receive p")?;
        let g = client_stream
            .receive()?
            .ok_or_else(|| "did not receive g")?;
        server_stream.send(&p)?;
        server_stream.send(&g)?;
        //Discard actual public keys
        client_stream.receive()?;
        server_stream.receive()?;
        //Send fake public keys
        client_stream.send(&p)?;
        server_stream.send(&p)?;
        let key = secret_to_key(&serialize(&BigNum::zero()));
        Ok(key)
    }
}

pub struct MitmFakePublicKey;

impl<T: Communicate> MitmForClientServer<T> for MitmFakePublicKey {
    type Mitm = MitmHandshakeFakePublicKey;
    type CS = ClientDeterminesParameters;
}

// Mitm used for challenge 35

pub enum FakeGeneratorMode {
    One,
    P,
    PMinusOne,
}

#[allow(non_snake_case)]
fn handshake_with_fake_generator<T: Communicate>(
    client_stream: &mut T,
    server_stream: &mut T,
    mode: &FakeGeneratorMode,
) -> Result<Vec<u8>> {
    let p = client_stream
        .receive()?
        .ok_or_else(|| "did not receive p")?;
    // Discard g
    client_stream
        .receive()?
        .ok_or_else(|| "did not receive g")?;

    server_stream.send(&p)?;

    let g_fake = compute_fake_generator(mode, &p);

    // Send fake g
    server_stream.send(&g_fake)?;

    server_stream
        .receive()?
        .ok_or_else(|| "did not receive p")?;
    server_stream
        .receive()?
        .ok_or_else(|| "did not receive g")?;

    client_stream.send(&p)?;

    // Send fake g
    client_stream.send(&g_fake)?;

    let A = client_stream
        .receive()?
        .ok_or_else(|| "did not receive A")?;
    let B = server_stream
        .receive()?
        .ok_or_else(|| "did not receive B")?;
    client_stream.send(&B)?;
    server_stream.send(&A)?;

    let secret = compute_secret(&mode, &A, &B);
    let key = secret_to_key(&secret);
    Ok(key)
}

fn compute_fake_generator(mode: &FakeGeneratorMode, p: &[u8]) -> Vec<u8> {
    let _1 = BigNum::one();
    serialize(&match mode {
        FakeGeneratorMode::One => _1,
        FakeGeneratorMode::P => deserialize(&p),
        FakeGeneratorMode::PMinusOne => &deserialize(&p) - &_1,
    })
}

#[allow(non_snake_case)]
fn compute_secret(mode: &FakeGeneratorMode, A: &[u8], B: &[u8]) -> Vec<u8> {
    let _0 = serialize(&BigNum::zero());
    let _1 = serialize(&BigNum::one());
    match mode {
        FakeGeneratorMode::One => _1,
        FakeGeneratorMode::P => _0,
        FakeGeneratorMode::PMinusOne => {
            /* In this case, both client and server use the generator p - 1.
             * But p - 1 is equal to -1 modulo p. Therefore A = (g ^ a) % p
             * is either equal to 1 or to -1, depending on whether a is even or odd,
             * and analogously for B and b. The shared secret is equal to g ^ (a * b) % p.
             * By noting that the product a * b is even iff at least one of a or b is even
             * we can compute the shared secret from the public keys as follows: */
            if A == &_1[..] || B == &_1[..] {
                _1
            } else {
                A.to_vec()
            }
        }
    }
}

// I could not get this to work in the type system
macro_rules! generator {
    ($handshake:ident, $mitm:ident, $mode:expr) => {
        pub struct $handshake;
        impl<T: Communicate> MitmHandshake<T> for $handshake {
            fn handshake(client_stream: &mut T, server_stream: &mut T) -> Result<Vec<u8>> {
                handshake_with_fake_generator(client_stream, server_stream, &$mode)
            }
        }

        pub struct $mitm;
        impl<T: Communicate> MitmForClientServer<T> for $mitm {
            type Mitm = $handshake;
            type CS = ServerCanOverrideParameters;
        }
    };
}

generator!(
    MitmHandshakeFakeGeneratorOne,
    MitmFakeGeneratorOne,
    FakeGeneratorMode::One
);
generator!(
    MitmHandshakeFakeGeneratorP,
    MitmFakeGeneratorP,
    FakeGeneratorMode::P
);
generator!(
    MitmHandshakeFakeGeneratorPMinusOne,
    MitmFakeGeneratorPMinusOne,
    FakeGeneratorMode::PMinusOne
);
