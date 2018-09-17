use bignum::BigNumTrait;
use digest::Digest;
use sha1::Sha1;

pub struct DH<T: BigNumTrait> {
    p: T,
    g: T,
    a: T,
}

pub fn secret_to_key(s: &[u8]) -> Vec<u8> {
    Sha1::digest(s)[0..16].to_vec()
}

pub fn serialize<T: BigNumTrait>(x: &T) -> Vec<u8> {
    x.to_bytes_be()
}

pub fn deserialize<T: BigNumTrait>(x: &[u8]) -> T {
    T::from_bytes_be(x)
}

impl<T: BigNumTrait> DH<T> {
    pub fn new() -> Self {
        let p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
                     020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
                     4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
                     ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
                     98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
                     9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";

        let p = T::from_hex_str(p_hex).unwrap(); // unwrap is ok
        let g = T::from_u32(2);
        Self::new_with(p, g)
    }

    pub fn new_with_parameters(p: &[u8], g: &[u8]) -> Self {
        Self::new_with(deserialize(p), deserialize(g))
    }

    fn new_with(p: T, g: T) -> Self {
        let a = T::gen_below(&p);
        DH { p, g, a }
    }

    pub fn parameters(&self) -> (Vec<u8>, Vec<u8>) {
        (serialize(&self.p), serialize(&self.g))
    }

    pub fn public_key(&self) -> Vec<u8> {
        serialize(&self.g.mod_exp(&self.a, &self.p))
    }

    #[allow(non_snake_case)]
    pub fn shared_key(&self, B: &[u8]) -> Vec<u8> {
        let B: T = deserialize(B);
        let s = B.mod_exp(&self.a, &self.p);
        secret_to_key(&serialize(&s))
    }
}

impl<T: BigNumTrait> Default for DH<T> {
    fn default() -> Self {
        Self::new()
    }
}
