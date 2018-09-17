use errors::*;

use dsa::{compute_sha1, DsaParams, Signature};

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

use serialize::Serialize;

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use super::challenge43::compute_private_key_from_k;

pub struct SignedHash {
    m: BigNum,
    signature: Signature<BigNum>
}

fn read_hashes_and_signatures_from_file() -> Result<Vec<SignedHash>, Error> {
    let path = Path::new("data/44.txt");
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let mut signed_hashes = Vec::new();
    let mut m = None;
    let mut r = None;
    let mut s = None;
    for line in reader.lines().map(|line| line.unwrap()) {
        if line.len() < 3 {
            continue;
        }

        match &line[0..3] {
            "m: " => m = Some(BigNum::from_hex_str(&line[3..])?),
            "r: " => r = Some(BigNum::from_dec_str(&line[3..])?),
            "s: " => s = Some(BigNum::from_dec_str(&line[3..])?),
            _ => continue,
        };

        if m.is_some() && r.is_some() && s.is_some() {
            signed_hashes.push(SignedHash {
                m: m.unwrap(), // unwrap is ok
                signature: Signature {
                    r: r.unwrap(), // unwrap is ok
                    s: s.unwrap() // unwrap is ok
                }});

            m = None;
            r = None;
            s = None;
        }
    }

    Ok(signed_hashes)
}

pub fn compute_private_key_from_reused_k(
    params: &DsaParams<BigNum>,
    &SignedHash { m: ref m1, signature: ref s1 }: &SignedHash,
    &SignedHash { m: ref m2, signature: ref s2 }: &SignedHash
) -> Result<BigNum, Error> {
    if s1.r != s2.r {
        bail!("Provided signatures do not have the same r.");
    }

    let q = &params.q;
    let s_diff = &(&s1.s - &s2.s).remainder(q);
    if s_diff == &BigNum::zero() {
        bail!("Provided signatures are not different.");
    }

    let k = &(m1 - m2).remainder(q) * &s_diff.invmod(q).unwrap(); // unwrap is ok

    Ok(compute_private_key_from_k(params, m1, s1, &k))
}

pub fn run() -> Result<(), Error> {
    let params = DsaParams::new();
    let signed_hashes = read_hashes_and_signatures_from_file()?;

    for (i, sh1) in signed_hashes.iter().enumerate() {
        for sh2 in signed_hashes[i + 1..].iter() {
            if sh1.signature.r != sh2.signature.r {
                continue;
            }

            let private_key = compute_private_key_from_reused_k(&params, &sh1, &sh2)?;
            let private_key_hex = private_key.to_hex_str();

            // Verify that the SHA1 of the hex representation of the private key is the one given in the
            // exercise.
            return compare_eq(
                "ca8f6f7c66fa362d40760d135b763eb8527d3d52",
                compute_sha1(private_key_hex.as_bytes())
                .to_hex()
                .as_ref());
        }
    }

    Err(ChallengeError::ItemNotFound("signatures with equal r".to_owned()).into())
}
