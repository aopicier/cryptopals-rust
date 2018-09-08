use errors::*;

use rsa::Rsa;

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

use set2::random_block;

fn find_signature(size: usize, suffix: &[u8]) -> Option<BigNum> {
    let mut prefix = vec![1u8];
    let one = BigNum::from_u32(1);
    let k = 3;
    //The loop does not seem to be necessary. Can I prove why?
    loop {
        let unused_space = size as i32 - 1 - prefix.len() as i32 - suffix.len() as i32;
        if unused_space < 0 {
            return None;
        }
        let fake_block = BigNum::from_bytes_be(&{
            let mut v = prefix.clone();
            v.extend_from_slice(suffix);
            v
        });
        let lower = fake_block.lsh(8 * unused_space as usize);
        let upper = (&fake_block + &one).lsh(8 * unused_space as usize);
        let r = (&upper - &one).root(k).0;
        let power = r.power(k);
        if power >= lower {
            return Some(r);
        }
        prefix.push(255);
    }
}

pub fn run() -> Result<(), Error> {
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
        block[i..i + suffix.len()] == suffix[..]
    };

    let fake_signature = find_signature(size, &suffix);
    compare_eq(true, verify_signature(&fake_signature.unwrap()))
}

