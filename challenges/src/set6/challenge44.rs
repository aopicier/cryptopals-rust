use errors::*;

use dsa::{DsaParams, DsaPublic, Signature};

use bignum::BigNumTrait;
use bignum::OpensslBigNum as BigNum;

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

pub fn run() -> Result<(), Error> {
    let params = DsaParams::generate();

    let y = BigNum::from_hex_str(
        "\
         2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
         13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
         5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
         f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
         f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
         2971c3de5084cce04a2e147821",
    )?;
    let public = DsaPublic { params: &params, y };

    let path = Path::new("data/44.txt");
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let mut messages = Vec::new();
    let mut signatures = Vec::new();
    let mut r = None;
    let mut s = None;
    for line in reader.lines().map(|line| line.unwrap()) {
        if line.len() < 3 {
            continue;
        }
        match &line[0..3] {
            "m: " => messages.push(BigNum::from_hex_str(&line[3..])?),
            "r: " => r = Some(BigNum::from_dec_str(&line[3..])?),
            "s: " => s = Some(BigNum::from_dec_str(&line[3..])?),
            _ => continue,
        };
        if r.is_some() && s.is_some() {
            signatures.push(Signature {
                r: r.unwrap(),
                s: s.unwrap(),
            });
            r = None;
            s = None;
        }
    }
    assert_eq!(messages.len(), signatures.len());
    for (i, (m1, s1)) in messages.iter().zip(signatures.iter()).enumerate() {
        for (m2, s2) in messages[i + 1..].iter().zip(signatures[i + 1..].iter()) {
            if s1.r != s2.r {
                continue;
            }
            let x = public.secret_key_from_two_signatures_with_same_k(m1, s1, m2, s2);
            // ~ echo -n "f1b733db159c66bce071d21e044a48b0e4c1665a" | sha1sum
            // ca8f6f7c66fa362d40760d135b763eb8527d3d52  -
            return compare_eq(
                BigNum::from_hex_str("f1b733db159c66bce071d21e044a48b0e4c1665a").unwrap(),
                x,
            );
        }
    }

    Err(ChallengeError::ItemNotFound("signatures with equal r".to_owned()).into())
}
