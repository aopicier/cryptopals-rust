use algo::{serialize, deserialize, UComputer, DefaultUComputer, SRP, ServerHandshake, LoginResult};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::marker::PhantomData;

use rand;
use rand::Rng;

use communication::Communicate;

use failure::{Error, err_msg};

use bignum::NumBigInt as BigNum;

struct SimplifiedUComputer;

impl UComputer for SimplifiedUComputer {
    fn compute_u<T: Communicate>(_: &BigNum, _: &BigNum, stream: &mut T) -> Result<BigNum, Error> {
        let mut rng = rand::thread_rng();
        let u: Vec<u8> = rng.gen_iter::<u8>().take(128).collect();
        stream.send(&u)?;
        Ok(deserialize(&u))
    }
}

struct ServerBase<U: UComputer> {
    params: SRP,
    user_database: HashMap<Vec<u8>, (Vec<u8>, BigNum)>,
    computer: PhantomData<U>
}

impl<U: UComputer> ServerBase<U> {
    fn new(params: SRP) -> Self {
        ServerBase {
            params,
            user_database: HashMap::new(),
            computer: PhantomData,
        }
    }

    fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<(), Error> {
        let user_name = stream.receive()?.ok_or_else(|| err_msg("user name"))?;

        // TODO Rewrite once NLL has landed
        match self.user_database.entry(user_name) {
            Entry::Occupied(o) => Self::authenticate_client(&self.params, stream, o.get()),
            Entry::Vacant(v) => {
                let password = stream.receive()?.ok_or_else(|| err_msg("password"))?;
                v.insert(self.params.password_to_verifier(&password));
                Ok(())
            }
        }
    }

    fn authenticate_client<T: Communicate> (
        params: &SRP,
        stream: &mut T,
        &(ref salt, ref v): &(Vec<u8>, BigNum),
        ) -> Result<(), Error> {
        let state = ServerHandshake::new(params, salt, v);
        let A = deserialize(&stream.receive()?.ok_or_else(|| err_msg("A"))?);
        let B = state.B();
        stream.send(salt)?;
        stream.send(&serialize(B))?;
        let u = U::compute_u::<T>(&A, &B, stream)?;
        let server_secret = state.compute_hashed_secret(&A, &u);
        let client_secret = stream
            .receive()?
            .ok_or_else(|| err_msg("client secret"))?;

        let login_result = if server_secret == client_secret { LoginResult::Success } else { LoginResult::Failure };
        stream.send(&[login_result as u8])?;
        Ok(())
    }
}

pub struct Server {
    base: ServerBase<DefaultUComputer>
}

impl Server {
    pub fn new() -> Self {
        Server {
            base: ServerBase::new(  SRP::new())
        }
    }

    pub fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<(), Error> {
        self.base.handle_client(stream)
    }
}

pub struct SimplifiedServer {
    base: ServerBase<SimplifiedUComputer>
}

impl SimplifiedServer {
    pub fn new() -> Self {
        SimplifiedServer {
            base: ServerBase::new(  SRP::new_with_k(0))
        }
    }

    pub fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<(), Error> {
        self.base.handle_client(stream)
    }
}
