use algo::{serialize, deserialize, SRP, ServerHandshake, LoginResult};
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use communication::Communicate;

use failure::{Error, err_msg};

use bignum::NumBigInt as BigNum;

pub struct Server {
    params: SRP,
    user_database: HashMap<Vec<u8>, (Vec<u8>, BigNum)>,
}

impl Server {
    pub fn new() -> Server {
        Server {
            params: SRP::new(),
            user_database: HashMap::new(),
        }
    }

    pub fn handle_client<T: Communicate>(&mut self, stream: &mut T) -> Result<(), Error> {
        let user_name = stream.receive()?.ok_or_else(|| err_msg("user name"))?;

        match self.user_database.entry(user_name) {
            Entry::Occupied(o) => authenticate_client(&self.params, stream, o.get()),
            Entry::Vacant(v) => {
                let password = stream.receive()?.ok_or_else(|| err_msg("password"))?;
                v.insert(self.params.password_to_secret(&password));
                Ok(())
            }
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
    let server_secret = state.compute_secret(&A);
    let client_secret = stream.receive()?.ok_or_else(|| err_msg("client secret"))?;
    let login_result = if server_secret == client_secret { LoginResult::Success } else { LoginResult::Failure };
    stream.send(&[login_result as u8])?;
    Ok(())
}
