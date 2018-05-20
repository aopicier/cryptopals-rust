use algo::{SRP, ClientHandshake, serialize, deserialize, LoginResult};
use communication::Communicate;
use failure::{Error, err_msg};

pub struct Client {
    params: SRP,
    user_name: Vec<u8>,
    password: Vec<u8>,
}

#[derive(Debug, Fail)]
#[fail(display = "server rejected login")]
struct LoginFailed();

impl Client {
    pub fn new(user_name: Vec<u8>, password: Vec<u8>) -> Self {
        Client {
            params: SRP::new(),
            user_name,
            password
        }
    }

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        stream.send(&self.user_name)?;
        stream.send(&self.password)?;
        Ok(())
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        stream.send(&self.user_name)?;
        let state = ClientHandshake::new(&self.params, &self.password);
        stream.send(&serialize(state.A()))?;
        let salt: Vec<u8> = stream.receive()?.ok_or_else(|| err_msg("salt"))?;
        let B = deserialize(&stream.receive()?.ok_or_else(|| err_msg("B"))?);
        let secret = state.compute_secret(&B, &salt);
        stream.send(&secret)?;
        let login_result = stream.receive()?.ok_or_else(|| err_msg("login result"))?;
        if login_result == [LoginResult::Success as u8] { Ok(()) } else { Err(LoginFailed().into()) }
    }
}
