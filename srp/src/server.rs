use crate::algo::{
    deserialize, serialize, DefaultUComputer, LoginResult, ServerHandshake, UComputer, SRP,
};
use std::collections::HashMap;
use std::marker::PhantomData;

use rand::Rng;

use crate::communication::Communicate;

use bignum::NumBigInt as BigNum;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

struct SimplifiedUComputer;

impl UComputer for SimplifiedUComputer {
    fn compute_u<T: Communicate>(_: &BigNum, _: &BigNum, stream: &mut T) -> Result<BigNum> {
        let mut rng = rand::thread_rng();
        let u: Vec<u8> = rng.gen_iter::<u8>().take(128).collect();
        stream.send(&u)?;
        Ok(deserialize(&u))
    }
}

struct ServerBase<U: UComputer> {
    params: SRP,
    user_database: HashMap<Vec<u8>, (Vec<u8>, BigNum)>,
    computer: PhantomData<U>,
}

impl<U: UComputer> ServerBase<U> {
    fn new(params: SRP) -> Self {
        ServerBase {
            params,
            user_database: HashMap::new(),
            computer: PhantomData,
        }
    }

    fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<()> {
        let user_name = stream.receive()?.ok_or_else(|| "user name")?;

        match self.user_database.get(&user_name) {
            Some(user_data) => Self::authenticate_client(&self.params, stream, user_data),
            None => {
                let password = stream.receive()?.ok_or_else(|| "password")?;
                let user_data = self.params.password_to_verifier(&password);
                self.user_database.insert(user_name, user_data);
                Ok(())
            }
        }
    }

    fn authenticate_client<T: Communicate>(
        params: &SRP,
        stream: &mut T,
        &(ref salt, ref v): &(Vec<u8>, BigNum),
    ) -> Result<()> {
        let state = ServerHandshake::new(params, salt, v);
        let A = deserialize(&stream.receive()?.ok_or_else(|| "A")?);
        let B = state.B();
        stream.send(salt)?;
        stream.send(&serialize(B))?;
        let u = U::compute_u::<T>(&A, &B, stream)?;
        let server_secret = state.compute_hashed_secret(&A, &u);
        let client_secret = stream.receive()?.ok_or_else(|| "client secret")?;

        let login_result = if server_secret == client_secret {
            LoginResult::Success
        } else {
            LoginResult::Failure
        };
        stream.send(&[login_result as u8])?;
        Ok(())
    }
}

pub trait ClientHandler: Send + 'static {
    fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<()>;
}

pub struct Server {
    base: ServerBase<DefaultUComputer>,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            base: ServerBase::new(SRP::default()),
        }
    }
}

impl ClientHandler for Server {
    fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<()> {
        self.base.handle_client(stream)
    }
}

pub struct SimplifiedServer {
    base: ServerBase<SimplifiedUComputer>,
}

impl Default for SimplifiedServer {
    fn default() -> Self {
        SimplifiedServer {
            base: ServerBase::new(SRP::new_with_k(0)),
        }
    }
}

impl ClientHandler for SimplifiedServer {
    fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<()> {
        self.base.handle_client(stream)
    }
}
