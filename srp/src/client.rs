use algo::{SRP, ClientHandshake, serialize, deserialize, LoginResult};
use communication::Communicate;
use failure::{Error, err_msg};

pub struct Client {
    params: SRP,
    user_name: Vec<u8>,
    password: Vec<u8>,
}

impl Client {
    pub fn new(user_name: Vec<u8>, password: Vec<u8>) -> Self {
        Client {
            params: SRP::new(),
            user_name: user_name,
            password: password
        }
    }

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        stream.send(&self.user_name)?;
        stream.send(&self.password)?;
        Ok(())
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<(bool), Error> {
        stream.send(&self.user_name)?;
        let state = ClientHandshake::new(&self.params);
        stream.send(&serialize(state.A()))?;
        let salt: Vec<u8> = stream.receive()?.ok_or(err_msg("salt"))?;
        let B = deserialize(&stream.receive()?.ok_or(err_msg("B"))?);
        let secret = state.compute_secret(&B, &salt, &self.password);
        stream.send(&secret)?;
        let login_result = stream.receive()?.ok_or(err_msg("login result"))?;
        Ok(login_result == &[LoginResult::Success as u8])
    }
}
