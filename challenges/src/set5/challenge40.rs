use bignum::OpensslBigNum as BigNum;
use bignum::{BigNumExt, BigNumTrait};
use errors::*;
use rsa::Rsa;

pub fn run() -> Result<(), Error> {
    let bits = 512;
    let m = BigNum::gen_random(bits - 1);
    let rsa1 = Rsa::generate(bits);
    let rsa2 = Rsa::generate(bits);
    let rsa3 = Rsa::generate(bits);
    let c1 = rsa1.encrypt(&m);
    let c2 = rsa2.encrypt(&m);
    let c3 = rsa3.encrypt(&m);
    let n1 = rsa1.n();
    let n2 = rsa2.n();
    let n3 = rsa3.n();
    let x1 = n2 * n3;
    let x2 = n1 * n3;
    let x3 = n1 * n2;
    /* Let N = n1*n2*n3. The following formula is based on the inverse function
     * IZ/(n1) x IZ(n2) x IZ(n3) -> IZ/(N)
     * from the Chinese Remainder Theorem. Of course this only works when n1, n2 and n3 don't have
     * any common divisors.
     *
     * We also use the following fact: As the public exponent of our encryption is hardcoded to 3,
     * we have m^3 = ci mod ni, hence also m^3 = c mod N. As m < min(n1, n2, n3), we have m^3 < N.
     * By definition, we also have c < N. Combining these statements we obtain m^3 = c in IZ (!),
     * so that we can recover m as the third root in IZ of c, which is easy to obtain. */

    let c = &(&(&(&(&c1 * &x1) * &x1.invmod(n1).unwrap())
        + &(&(&c2 * &x2) * &x2.invmod(n2).unwrap()))
        + &(&(&c3 * &x3) * &x3.invmod(n3).unwrap()))
        % &(&(n1 * n2) * n3);
    compare_eq(&m, &c.root(3).0)
}
