use algo;
use algo::{deserialize, serialize, LoginResult, SRP};
use communication::Communicate;

use failure::{err_msg, Error};

use bignum::BigNumTrait;
use bignum::NumBigInt as BigNum;

pub struct PasswordOracle {
    g: BigNum,
    N: BigNum,
    A: BigNum,
    client_secret: Vec<u8>,
}

impl PasswordOracle {
    pub fn is_password(&self, password_candidate: &[u8]) -> bool {
        self.password_to_client_secret(password_candidate) == self.client_secret
    }

    fn password_to_client_secret(&self, password_candidate: &[u8]) -> Vec<u8> {
        let g = &self.g;
        let N = &self.N;
        let A = &self.A;

        let salt = &[];
        let B = g;
        let u = g;

        let x = algo::compute_x(salt, password_candidate);

        // The crucial point is that for B = g the expression
        // (B ^ a) % N
        // from the client computation is equal to A.
        let S = &(A * &B.mod_exp(&(u * &x), N)) % N;
        algo::hash_secret(&S, salt)
    }
}

// An attacker posing as the server and sending the following parameters
// to the client:
// 1) salt = &[]
// 2) B = g
// 3) u = g

pub struct Mitm {
    params: SRP,
}

impl Default for Mitm {
    fn default() -> Self {
        Mitm {
            params: SRP::new_with_k(0),
        }
    }

}
impl Mitm {
    pub fn handle_client<T: Communicate>(&self, stream: &mut T) -> Result<PasswordOracle, Error> {
        let _ = stream.receive()?.ok_or_else(|| err_msg("user name"))?;
        let A: BigNum = deserialize(&stream.receive()?.ok_or_else(|| err_msg("A"))?);
        let g = self.params.g();
        let salt = &[];
        let B = g;
        let u = g;

        stream.send(salt)?;
        stream.send(&serialize(B))?;
        stream.send(&serialize(u))?;

        let client_secret = stream.receive()?.ok_or_else(|| err_msg("client secret"))?;

        stream.send(&[LoginResult::Success as u8])?;
        Ok(PasswordOracle {
            g: g.clone(),
            N: self.params.N().clone(),
            A,
            client_secret,
        })
    }

    pub fn password_to_client_secret(&self, A: &BigNum, password_candidate: &[u8]) -> Vec<u8> {
        let g = self.params.g();
        let N = self.params.N();

        let salt = &[];
        let B = g;
        let u = g;

        let x = algo::compute_x(salt, password_candidate);

        // The crucial point is that for B = g the expression
        // (B ^ a) % N
        // from the client computation is equal to A.
        let S = &(A * &B.mod_exp(&(u * &x), N)) % N;
        algo::hash_secret(&S, salt)
    }
}
