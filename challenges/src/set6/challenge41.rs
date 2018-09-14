use errors::*;

use rsa::Rsa;

use bignum::BigNumTrait;
use bignum::OpensslBigNum as BigNum;

const BITS:usize = 512;

struct Server {
    rsa: Rsa<BigNum>,
    cleartext: BigNum,
    ciphertext: BigNum,
}

impl Server {
    fn new() -> Self {
        let rsa = Rsa::<BigNum>::generate(BITS);
        let cleartext = BigNumTrait::gen_random(BITS - 1);
        let ciphertext = rsa.encrypt(&cleartext);
        Server { rsa, cleartext, ciphertext }
    }

    fn n(&self) -> &BigNum {
        &self.rsa.n()
    }

    fn get_ciphertext(&self) -> &BigNum {
        &self.ciphertext
    }

    fn encrypt(&self, cleartext: &BigNum) -> BigNum {
        self.rsa.encrypt(cleartext)
    }

    fn decrypt(&self, ciphertext: &BigNum) -> Option<BigNum> {
        // Reject ciphertext itself
        if ciphertext == &self.ciphertext {
            return None;
        }
        Some(self.rsa.decrypt(ciphertext))
    }

    fn verify_solution(&self, candidate: &BigNum) -> Result<(), Error> {
        compare_eq(&self.cleartext, candidate)
    }
}

pub fn run() -> Result<(), Error> {
    let server = Server::new();
    let ciphertext = server.get_ciphertext();

    let n = server.n();
    let s = &BigNum::from_u32(2);
    let t = &s.invmod(n).unwrap(); // unwrap is ok

    let altered_ciphertext = &(ciphertext * &server.encrypt(s)) % n;
    let altered_cleartext = server
        .decrypt(&altered_ciphertext)
        .ok_or_else(|| err_msg("wrong input to oracle"))?;

    let cleartext = &(&altered_cleartext * t) % n;
    server.verify_solution(&cleartext)
}
