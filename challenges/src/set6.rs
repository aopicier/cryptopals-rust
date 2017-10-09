use dsa;
use dsa::{DsaParams,DsaPrivate,DsaPublic,Signature,rand_range_safe};
use rsa::Rsa;

use bignum::BigNum as BigNum;
use bignum::{BigNumTrait, BigNumExt};
use serialize::{Serialize,from_base64};

use rand;
use rand::Rng;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::path::Path;

use std::cmp;

use set2::random_block;

use errors::*;

fn matasano6_41() -> Result<()> {
    let bits = 512;
    let rsa = Rsa::<BigNum>::generate(bits);

    let m = BigNumTrait::gen_random(bits-1);
    let c = rsa.encrypt(&m);

    let oracle = |x: &BigNum| -> Option<BigNum> {
        if *x == c {
            return None;
        }
        Some(rsa.decrypt(x))
    };

    let s = <BigNum as BigNumTrait>::gen_random(bits-1);
    //TODO We should check that s > 1 and that s and rsa.n() have no common divisors
    let t = s.invmod(rsa.n()).ok_or("s and n are not coprime")?;

    let c2 = &(&c * &rsa.encrypt(&s)) % rsa.n();
    let m2 = oracle(&c2).ok_or("wrong input to oracle")?;
    compare(m, &(&m2 * &t) % rsa.n())
}

fn find_signature(size: usize, suffix: &[u8]) -> Option<BigNum> {
    let mut prefix = vec![1u8];
    //prefix.extend_from_slice(&vec![255; 14]);
    let one = <BigNum as BigNumTrait>::from_u32(1);
    let k = 3;
    //The loop does not seem to be necessary. Can I prove why?
    loop {
        let unused_space = size as i32 - 1 - prefix.len() as i32 - suffix.len() as i32;
        //println!("{}", unused_space);
        if unused_space < 0 {
            return None;
        }
        let fake_block = <BigNum as BigNumTrait>::from_bytes_be(&{
            let mut v = prefix.clone();
            v.extend_from_slice(suffix);
            v
        });
        let lower = fake_block.lsh(8*unused_space as usize);
        let upper = (&fake_block + &one).lsh(8*unused_space as usize);
        let r = (&upper - &one).root(k).0;
        let power = r.power(k);
        //println!("{:?}", lower.to_vec());
        //println!("{:?}", power.to_vec());
        //println!("{:?}", upper.to_vec());
        //println!("");
        if power >= lower {
            return Some(r);
        }
        prefix.push(255);
    }
}

fn matasano6_42() -> Result<()> {
    //We lose leading zeros during the conversion to BigNum. We therefore omit it from prefix and 
    //check that the length of the block is one less than the length of n.
    let bits = 1024;
    let rsa = Rsa::<BigNum>::generate(bits);
    let size = rsa.n().bytes() as usize;
    let hash = random_block(); //We want to forge a signature containing this hash
    let suffix = {
        let mut v = vec![0u8];
        v.extend_from_slice(&hash);
        v
    };

    //Verify the signature by checking that the encrypted block *starts with* (this is the flaw) 
    //01 || ff || ff || ... || ff || suffix
    let verify_signature = |signature: &BigNum| -> bool {
        let block = BigNumTrait::to_bytes_be(&rsa.encrypt(signature));
        assert_eq!(block.len(), size - 1);
        if block[0] != 1 {
            return false;
        }
        let mut i = 1;
        while i < block.len() && block[i] == 255 {
            i += 1;
        }
        if i + suffix.len() >= block.len() {
            return false;
        }
        block[i..i+suffix.len()] == suffix[..]
    };

    let fake_signature = find_signature(size, &suffix);
    compare(true, verify_signature(&fake_signature.unwrap()))
}

fn matasano6_43() -> Result<()> {
    let params = DsaParams::generate();

    let y = BigNum::from_hex_str("\
      84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
      abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
      e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
      1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
      bb283e6633451e535c45513b2d33c99ea17")?;
    let public = DsaPublic { params: &params, y: y };
    let m = BigNum::from_hex_str("d2d0714f014a9784047eaeccf956520045c45265")?;
    let signature = Signature {
        r: BigNum::from_dec_str("548099063082341131477253921760299949438196259240")?,
        s: BigNum::from_dec_str("857042759984254168557880549501802188789837994940")?};


    let zero = BigNum::zero();
    let one = BigNum::one();
    let private = 
        (0u32..(1<<16)+1)
            .map(BigNumTrait::from_u32)
            .map(|k| public.secret_key_from_k(&m, &signature, &k))
            .filter(|x| x != &zero && x != &one)
            .map(|x| DsaPrivate {params: &params, x: x })
            .find(|private| DsaPublic::generate(private).y == public.y);

    // ~ echo -n 15fb2873d16b3e129ff76d0918fd7ada54659e49 | sha1sum
    // 0954edd5e0afe5542a4adf012611a91912a3ec16  -
    compare(Some(BigNum::from_hex_str("15fb2873d16b3e129ff76d0918fd7ada54659e49")?), private.map(|p| p.x))
}

fn matasano6_44() -> Result<()> {
    let params = DsaParams::generate();

    let y = BigNum::from_hex_str("\
    2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
    13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
    5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
    f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
    f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
    2971c3de5084cce04a2e147821")?;
    let public = DsaPublic { params: &params, y: y };

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
            signatures.push(Signature { r : r.unwrap(), s : s.unwrap() });
            r = None;
            s = None;
        }
    }
    assert_eq!(messages.len(), signatures.len());
    for (i, (m1, s1)) in messages.iter().zip(signatures.iter()).enumerate() {
        for (m2, s2) in messages[i+1..].iter().zip(signatures[i+1..].iter()) {
            if s1.r != s2.r {
                continue;
            }
            let x = public.secret_key_from_two_signatures_with_same_k(m1, s1, m2, s2);
            // ~ echo -n "f1b733db159c66bce071d21e044a48b0e4c1665a" | sha1sum
            // ca8f6f7c66fa362d40760d135b763eb8527d3d52  -
            return compare(BigNum::from_hex_str("f1b733db159c66bce071d21e044a48b0e4c1665a").unwrap(), x);
        }
    }
    bail!(ErrorKind::ItemNotFound("signatures with equal r".to_owned()));
}

fn matasano6_45() -> Result<()> {
    let params = DsaParams::<BigNum>::generate();
    let private = DsaPrivate::generate(&params);
    let public = DsaPublic::generate(&private);
    // It is not possible to fake a signature for g = 0 with our verification routine because r 
    // would have to be 0. We therefore skip this part of the exercise.
    let params_fake = DsaParams { p: BigNumTrait::clone(&params.p), q: BigNumTrait::clone(&params.q), g: BigNumTrait::one() };
    //let private_fake = DsaPrivate { params: &params_fake, x: clone(&private.x) };
    let public_fake = DsaPublic { params: &params_fake, y: BigNumTrait::clone(&public.y) };

    let signature = dsa::fake_signature(&public_fake);

    //Arbitrary message
    let m = rand_range_safe(&params.q);
    compare(true, public_fake.verify_signature(&m, &signature))
}

// `oracle` tells us whether the cleartext corresponding to a ciphertext is even or odd.
// Let c be an arbitrary ciphertext with corresponding cleartext m. Then the cleartext 
// corresponding to enc(2)*c is 2m % n. As n is odd, this is even if and only if 2m < n, so
// (*) oracle(enc(2) * c) == true <=> 2m < n.
//
// Now assume that 
// (**) (l-1) * n <= 2^k * m < l * n for some k >= 0 and some 1 <= l <= 2^k.
// Of course then also (2l - 2) * n <= 2^(k+1) * m < 2l * n.
// We want to find how on which side of (2l - 1) * n the cleartext m is lying.
//
// The cleartext corresponding to enc(2^k) * c is 
// 2^k * m mod n = 2^k * m - (l-1) * n.
// Applying (*) for enc(2^k) * c instead of c gives
// oracle(enc(2^(k+1)) * c) == true <=> 2 * (2^k * m - (l-1) * n) < n <=> 2^(k+1) * m < (2l-1)n.
// This allows us to pass from k to k+1 in (**) and iteratively we obtain more and more precise 
// bounds for m. For k = `number of bits in n` we obtain equality.

fn matasano6_46() -> Result<()> {
    let rsa = Rsa::generate(1024);
    let _0 = BigNum::zero();
    let _1 = BigNum::one();
    let _2 = <BigNum as BigNumTrait>::from_u32(2);
    let oracle = |ciphertext: &BigNum| -> bool {
        // !rsa.decrypt(ciphertext).is_bit_set(0)
        &rsa.decrypt(ciphertext) % &_2 == _0
    };
    let cleartext = from_base64("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")?.to_hex();
    let m = BigNum::from_hex_str(&cleartext)?;
    let mut c = rsa.encrypt(&m);
    let mut l = BigNum::one();
    let two = <BigNum as BigNumTrait>::from_u32(2);
    let factor = rsa.encrypt(&two);
    let k = rsa.n().bits() as usize;
    for _ in 0..k {
        c = &c * &factor;
        l = &l * &two;
        if oracle(&c)
        {
            l = &l - &_1;
        }
    }
    let result = (rsa.n() * &l).rsh(k);
    compare(b"That's why I found you don't play around with the Funky Cold Medina".as_ref(), &BigNumTrait::to_bytes_be(&result))
}

#[allow(non_snake_case)]
fn matasano6_47_48(rsa_bits: usize) -> Result<()> {
    let _0 = BigNum::zero();
    let _1 = BigNum::one();
    let _2 = <BigNum as BigNumTrait>::from_u32(2);
    let _3 = <BigNum as BigNumTrait>::from_u32(3);

    let rsa = Rsa::<BigNum>::generate(rsa_bits);
    let n = rsa.n();
    let k = n.bytes() as usize;
    let B = _1.lsh(8*(k - 2));
    let _2B = &_2 * &B;
    let _3B = &_3 * &B;

    let oracle = |ciphertext: &BigNum| -> bool {
        let cleartext = rsa.decrypt(ciphertext);
        cleartext.rsh(8*(k-2)) == _2
    };

    let cleartext = b"kick it, CC";
    let cleartext_len = cleartext.len();
    assert!(cleartext_len <= k - 11);
    let mut padded_cleartext = vec![2u8];
    let mut rng = rand::thread_rng();
    padded_cleartext.extend((0..(k - 3 - cleartext_len)).map(|_| rng.gen_range(1, 256) as u8));
    padded_cleartext.push(0);
    padded_cleartext.extend_from_slice(cleartext);
    let m: BigNum = BigNumTrait::from_bytes_be(&padded_cleartext);
    let c = rsa.encrypt(&m);

    let mut M_prev = vec![(BigNumTrait::clone(&_2B), &_3B - &_1)];
    let mut s_prev = BigNumTrait::clone(&_1);
    let mut i = 1;

    loop {
        // Step 2
        let mut si;
        if i == 1 {
            // Step 2.a
            si = n.ceil_div(&_3B).0;
            while !oracle(&(&c * &rsa.encrypt(&si)))
            {
                si = &si + &_1;
            }
        } else if M_prev.len() >= 2 {
            // Step 2.b
            si = &s_prev + &_1;
            while !oracle(&(&c * &rsa.encrypt(&si)))
            {
                si = &si + &_1;
            }
        } else {
            // Step 2.c
            let (ref a, ref b) = M_prev[0];
            let mut ri = (&_2 * &(&(b * &s_prev) - &_2B)).ceil_div(n).0;
            'outer: loop {
                si = (&_2B + &(&ri * n)).ceil_div(b).0;
                let U = (&_3B + &(&ri * n)).ceil_div(a).0;
                while si < U {
                    if oracle(&(&c * &rsa.encrypt(&si))) {
                        break 'outer;
                    }
                    si = &si + &_1;
                }
                ri = &ri + &_1;
            }
        }

        let mut Mi = Vec::new();
        for &(ref a, ref b) in &M_prev {
            let mut r = (&(&(a * &si) - &_3B) + &_1).ceil_div(n).0;
            let U = (&(b * &si) - &_2B).floor_div(n).0;
            while r <= U {
                Mi.push(
                    (
                        cmp::max(BigNumTrait::clone(a), (&_2B + &(&r * n)).ceil_div(&si).0),
                        cmp::min(BigNumTrait::clone(b), (&(&_3B - &_1) + &(&r * n)).floor_div(&si).0)
                    ));
                r = &r + &_1;
            }
        }

        Mi.sort();
        Mi.dedup();
        if Mi.len() == 1 && Mi[0].0 == Mi[0].1 {
            return compare(&m, &Mi[0].0);
        }
        i += 1;
        s_prev = si;
        M_prev = Mi;
    }
}

pub fn run() {
    println!("Set 6");
    run_exercise(matasano6_41, 41);
    run_exercise(matasano6_42, 42);
    run_exercise(matasano6_43, 43);
    run_exercise(matasano6_44, 44);
    run_exercise(matasano6_45, 45);
    run_exercise(matasano6_46, 46);
    run_exercise(|| matasano6_47_48(128), 47);
    run_exercise(|| matasano6_47_48(384), 48);
}

