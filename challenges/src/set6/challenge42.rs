use errors::*;

use rsa::Rsa;

use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};

use sha1;

const BITS: usize = 1024;

struct Server {
    rsa: Rsa<BigNum>
}

fn get_hash(message: &[u8]) -> Vec<u8> {
    let mut sha1 = sha1::Sha1::new();
    sha1.update(message);
    sha1.digest().bytes().to_vec()
}

impl Server {
    fn new() -> Self {
        Server { rsa: Rsa::generate(BITS) }
    }

    fn n(&self) -> &BigNum {
        &self.rsa.n()
    }

    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        let rsa = &self.rsa;
        let n = rsa.n();
        let signature_num = &BigNum::from_bytes_be(signature);
        if signature_num >= n {
            return false;
        }

        let plaintext = rsa.encrypt(signature_num).to_bytes_be();

        // Coming from a BigNum, the plaintext does not include any leading zeroes.
        // We therefore check that the length is one less than the length of n.
        if plaintext.len() != n.bytes() - 1 {
            return false;
        }

        // Verify that plaintext *starts with* (this is the flaw)
        // 01 || ff || ff || ... || ff || 00 || hash

        if plaintext[0] != 1 {
            return false;
        }

        let mut i = 1;
        while i < plaintext.len() && plaintext[i] == 255 {
            i += 1;
        }

        if i >= plaintext.len() || plaintext[i] != 0 {
            return false;
        }
        i += 1;

        let hash = get_hash(message);
        if i + hash.len() > plaintext.len() {
            return false;
        }

        plaintext[i..i + hash.len()] == hash[..]
    }

    // Not really required for the exercise
    fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        let hash = get_hash(message);
        let len = self.rsa.n().bytes() - 1;
        let mut plaintext = Vec::with_capacity(len);
        plaintext.push(1);
        for _ in 1..len - 1 - hash.len() {
            plaintext.push(255);
        }
        plaintext.push(0);
        plaintext.extend_from_slice(&hash);
        self.rsa.decrypt(&BigNum::from_bytes_be(&plaintext)).to_bytes_be()
    }
}


 /* We first prove a general observation concerning third roots of natural numbers.
  * Let k = 2^l be a positive natural number which is a power of two.
  * Let x be some positive natural number.
  *
  * Denote by crt the cube root function on positive real numbers. Assume that
  * (1) floor( crt((x + 1)k - 1) ) < crt(xk).
  * As y - 1 < floor(y) for any real number r, we have
  * crt((x + 1)k - 1) < crt(xk) + 1.
  * Taking  the third power yields
  * (x + 1)k - 1 < xk + 3*crt(xk) + 3*crt(xk)^2 + 1,
  * which simplifies to
  * (2) k < 3*crt(xk) + 3*crt(xk)^2 + 2.
  *
  * We now determine an upper bound for the right hand side of (2).
  * As crt(xk) >= 1, we have
  * 3*crt(xk) + 3*crt(xk)^2 + 2 <= 3*crt(xk)^2 + 3*crt(xk)^2 + 2*crt(xk)^2 = 8*crt(xk)^2.
  * Denote by y a natural number such that x <= 2^y. Then
  * 8*crt(xk)^2 <= 2^(2(l + y)/3 + 3).
  *
  * Combining this bound with (2) yields
  * 2^l <= 2^(2(l + y)/3 + 3), or (l - 9)/2 <= y.
  *
  * Reversing the implication, we find that if y < (l - 9)/2, then (1) cannot hold, i.e.
  * (3) floor( crt((x + 1)k - 1) ) >= crt(xk).
  *
  * Finally, note that (3) is equivalent to the existence of a natural number r with
  * xk <= r^3 <= (x + 1)k - 1, as floor( crt((x + 1)k - 1) ) is the biggest natural number
  * r with r^3 <= (x + 1)k - 1.
  *
  * Summarizing: If x <= 2^y for some natural number y < (l - 9)/2, then there is a natural
  * number r with x2^l <= r^3 <= (x + 1)2^l - 1. */

fn forge_signature(len: usize, message: &[u8]) -> Vec<u8> {
    let hash = &get_hash(message);

    /* Search for a plaintext of length `len` of the form
     * (F) 01 || ff || ff || ... || ff || 00 || hash || *
     * which has a third root in the natural numbers.
     *
     * In fact we can always achieve this without any ff bytes in the prefix.
     * Interpret
     * 01 || 00 || hash
     * as a big-endian number x. The length of x in bytes is 2 + hash.len() and we have
     * x <= 2^(8*(2 + hash.len())). Let l = 8(len - 2 - hash.len()) be the number
     * of bits we can fill arbitrarily. Then the numbers of the form (F) above
     * (in big-endian) are precisely the natural numbers between
     * x2^l and (x + 1)2^l - 1. As 8*(2 + hash.len()) is small compared to l, we
     * know by the general observations above that floor( crt((x + 1)k - 1) )
     * is a signature which will fool the server.
     *
     * Note that we can just as easily forge a signature with several ff bytes in the prefix
     * as long as 8*(2 + hash.len() + number of ff bytes) < (l - 9)/2.
     * */

    let x = BigNum::from_bytes_be(&{
        let mut v = Vec::with_capacity(2 + hash.len());
        v.push(1);
        v.push(0);
        v.extend_from_slice(hash);
        v
    });
    let l = 8 * (len - 2 - hash.len()) as usize;
    let _1 = BigNum::from_u32(1);
    let r = (&(&x + &_1).lsh(l) - &_1).root(3).0;
    r.to_bytes_be()
}

pub fn run() -> Result<(), Error> {
    let server = Server::new();
    {
        // Make sure that our server accepts valid signatures
        let message = &b"foo"[..];
        let signature = server.sign_message(message);
        compare_eq(true, server.verify_signature(message, &signature))?;
    }

    // Now we forge a signature for the following message
    let message = &b"hi mom"[..];
    let len = server.n().bytes() - 1;
    let forged_signature = forge_signature(len, message);

    compare_eq(true, server.verify_signature(message, &forged_signature))
}
