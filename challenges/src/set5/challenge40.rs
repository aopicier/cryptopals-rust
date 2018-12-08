use crate::errors::*;
use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};
use rsa::Rsa;

const BITS: usize = 512;

struct Server {
    secret: BigNum,
}

impl Server {
    fn new() -> Self {
        Server {
            secret: BigNum::gen_random(BITS - 1),
        }
    }

    fn get_ciphertexts(&self) -> ((BigNum, BigNum), (BigNum, BigNum), (BigNum, BigNum)) {
        let secret = &self.secret;
        loop {
            let rsa1: Rsa<BigNum> = Rsa::generate(BITS);
            let rsa2 = Rsa::generate(BITS);
            let rsa3 = Rsa::generate(BITS);
            let n1 = rsa1.n();
            let n2 = rsa2.n();
            let n3 = rsa3.n();

            // Make sure that n1, n2 and n3 are pairwise coprime. Otherwise the attack will
            // not work.
            if n1.invmod(n2).is_none() || n1.invmod(n3).is_none() || n2.invmod(n3).is_none() {
                continue;
            }

            let c1 = rsa1.encrypt(secret);
            let c2 = rsa2.encrypt(secret);
            let c3 = rsa3.encrypt(secret);

            return ((c1, n1.clone()), (c2, n2.clone()), (c3, n3.clone()));
        }
    }

    fn verify_solution(&self, candidate: &BigNum) -> Result<(), Error> {
        compare_eq(&self.secret, candidate)
    }
}

pub fn run() -> Result<(), Error> {
    let server = Server::new();
    let ((ref c1, ref n1), (ref c2, ref n2), (ref c3, ref n3)) = server.get_ciphertexts();

    /* Let N = n1 * n2 * n3. Denote by c the image of (c1, c2, c3) under the isomorphism
     * IZ/(n1) x IZ(n2) x IZ(n3) -> IZ/(N) from the Chinese Remainder Theorem
     * (we have ensured above that n1, n2 and n3 don't have any common divisors).
     *
     * Let m be the secret we want to recover. As the public exponent of our encryption is
     * hardcoded to 3, we have m^3 = ci mod ni, hence also m^3 = c mod N. As m < min(n1, n2, n3),
     * we have m^3 < N.  By definition, we also have c < N.
     * Combining these statements we obtain m^3 = c in IZ (!), so that we can recover m as the third
     * root in IZ of c, which is easy to obtain. */

    let x1 = &(n2 * n3);
    let x2 = &(n1 * n3);
    let x3 = &(n1 * n2);

    // We have ensured that the following inverses exist
    let y1 = &x1.invmod(n1).unwrap(); // unwrap is ok
    let y2 = &x2.invmod(n2).unwrap(); // unwrap is ok
    let y3 = &x3.invmod(n3).unwrap(); // unwrap is ok

    let z1 = &(&(c1 * x1) * y1);
    let z2 = &(&(c2 * x2) * y2);
    let z3 = &(&(c3 * x3) * y3);

    let c = &(&(z1 + z2) + z3) % &(&(n1 * n2) * n3);

    server.verify_solution(&c.root(3).0)
}
