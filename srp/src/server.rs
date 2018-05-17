use algo::{serialize, deserialize, SRP, ServerHandshake, LoginResult};
use std::collections::HashMap;

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
        let user_name = stream.receive()?.ok_or(err_msg("user name"))?;
        // Unfortunately the obvious match on self.user_database.get(&user_name) 
        // runs into borrow checker issues.
        let client_known = self.user_database.contains_key(&user_name);
        if  client_known {
            let user_data = self.user_database.get(&user_name).unwrap();
            return self.authenticate_client(stream, user_data);
        } else {
            return self.register_new_client(stream, user_name);
        }
    }

    pub fn authenticate_client<T: Communicate> (
        &self,
        stream: &mut T,
        &(ref salt, ref v): &(Vec<u8>, BigNum),
    ) -> Result<(), Error> {
        let state = ServerHandshake::new(&self.params, v);
        let A = deserialize(&stream.receive()?.ok_or(err_msg("A"))?);
        let B = state.B();
        stream.send(salt)?;
        stream.send(&serialize(B))?;
        let server_secret = state.compute_secret(&A, salt, v);
        let client_secret = stream.receive()?.ok_or(err_msg("client secret"))?;
        let login_result = if server_secret == client_secret { LoginResult::Success } else { LoginResult::Failure };
        stream.send(&[login_result as u8])?;
        Ok(())
    }

    pub fn register_new_client<T: Communicate>(&mut self, stream: &mut T, user_name: Vec<u8>) -> Result<(), Error> {
        let password = stream.receive()?.ok_or(err_msg("password"))?;
        let salt = self.params.generate_salt();
        let secret = self.params.password_to_secret(&salt, password);
        self.user_database.insert(user_name, (salt, secret));
        Ok(())
    }
}
