extern crate num;
extern crate rand;
extern crate serialize;

use bignum;
use sha1::Sha1;

pub struct DH<T: bignum::BigNumTrait> {
    p: T,
    g: T,
    a: T,
}

pub fn secret_to_key(s: &[u8]) -> Vec<u8> {
    let mut m = Sha1::new();
    m.update(&s);
    m.digest()[0..16].to_vec()
}

impl<T: bignum::BigNumTrait> DH<T> {
    pub fn new() -> Self {
        DH {p: T::zero(), g: T::zero(), a: T::zero()}
    }

    pub fn init(&mut self) {
        let p_hex = 
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
            020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
            4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
            ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
            98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
            9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";

        let p = T::from_hex_str(p_hex).unwrap();
        let g = T::from_u32(2);
        //let p = 37.to_biguint().unwrap();
        //let g = 5.to_biguint().unwrap();
        self.p = p;
        self.g = g;
    }

    pub fn init_with_parameters(&mut self, p: Vec<u8>, g: Vec<u8>) {
        self.p = T::from_bytes_be(&p);
        self.g = T::from_bytes_be(&g);
    }

    pub fn parameters(&self) -> (Vec<u8>, Vec<u8>) {
        (self.p.to_bytes_be(), self.g.to_bytes_be())
    }

    fn generate_private_key(&mut self) {
        //let mut rng = rand::thread_rng();
        let a = T::gen_below(&self.p);
        self.a = a;
    }

    pub fn public_key(&mut self) -> Vec<u8> {
        self.generate_private_key();
        self.g.mod_exp(&self.a, &self.p).to_bytes_be()
    }

    #[allow(non_snake_case)]
    pub fn shared_key(&mut self, B: &Vec<u8>) -> Vec<u8> {
        let B = T::from_bytes_be(&B);
        let s = B.mod_exp(&self.a, &self.p);
        secret_to_key(&T::to_bytes_be(&s))
    }
}
