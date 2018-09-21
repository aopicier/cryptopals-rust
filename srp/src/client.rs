use algo::{
    deserialize, hash_secret, serialize, zero, BigNum, ClientHandshake, DefaultUComputer,
    LoginResult, UComputer, SRP,
};
use communication::Communicate;
use failure::{err_msg, Error};
use std::marker::PhantomData;

#[derive(Debug, Fail)]
#[fail(display = "server rejected login")]
struct LoginFailed();

struct ClientBase<U: UComputer> {
    params: SRP,
    user_name: Vec<u8>,
    password: Vec<u8>,
    computer: PhantomData<U>,
}

impl<U: UComputer> ClientBase<U> {
    fn new(params: SRP, user_name: Vec<u8>, password: Vec<u8>) -> Self {
        ClientBase {
            params,
            user_name,
            password,
            computer: PhantomData,
        }
    }

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        stream.send(&self.user_name)?;
        stream.send(&self.password)?;
        Ok(())
    }

    fn login<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        stream.send(&self.user_name)?;
        let state = ClientHandshake::new(&self.params);
        let A = state.A();
        stream.send(&serialize(A))?;
        let salt: Vec<u8> = stream.receive()?.ok_or_else(|| err_msg("salt"))?;
        let B = deserialize(&stream.receive()?.ok_or_else(|| err_msg("B"))?);
        let u = U::compute_u(&A, &B, stream)?;
        let secret = state.compute_hashed_secret(&B, &u, &salt, &self.password);
        stream.send(&secret)?;
        let login_result = stream.receive()?.ok_or_else(|| err_msg("login result"))?;
        if login_result == [LoginResult::Success as u8] {
            Ok(())
        } else {
            Err(LoginFailed().into())
        }
    }
}

struct SimplifiedUComputer;

impl UComputer for SimplifiedUComputer {
    fn compute_u<T: Communicate>(_: &BigNum, _: &BigNum, stream: &mut T) -> Result<BigNum, Error> {
        let u_raw = stream.receive()?.ok_or_else(|| err_msg("u"))?;
        Ok(deserialize(&u_raw))
    }
}

pub struct Client {
    base: ClientBase<DefaultUComputer>,
}

impl Client {
    pub fn new(user_name: Vec<u8>, password: Vec<u8>) -> Self {
        Client {
            base: ClientBase::new(SRP::new(), user_name, password),
        }
    }

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        self.base.register(stream)
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        self.base.login(stream)
    }
}

pub struct SimplifiedClient {
    base: ClientBase<SimplifiedUComputer>,
}

impl SimplifiedClient {
    pub fn new(user_name: Vec<u8>, password: Vec<u8>) -> Self {
        SimplifiedClient {
            base: ClientBase::new(SRP::new_with_k(0), user_name, password),
        }
    }

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        self.base.register(stream)
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        self.base.login(stream)
    }
}

pub struct FakeClientWithZeroKey {
    user_name: Vec<u8>,
}

impl FakeClientWithZeroKey {
    pub fn new(user_name: Vec<u8>) -> Self {
        FakeClientWithZeroKey { user_name }
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<(), Error> {
        stream.send(&self.user_name)?;
        let _0 = zero();

        // Send zero for A
        stream.send(&serialize(&_0))?;

        let salt: Vec<u8> = stream.receive()?.ok_or_else(|| err_msg("salt"))?;

        // Discard B
        stream.receive()?.ok_or_else(|| err_msg("B"))?;

        // If A is zero, the S computed by the server is also zero.
        // The following hashed secret will therefore fool the server.
        let secret = hash_secret(&_0, &salt);
        stream.send(&secret)?;

        let login_result = stream.receive()?.ok_or_else(|| err_msg("login result"))?;

        if login_result == [LoginResult::Success as u8] {
            Ok(())
        } else {
            Err(LoginFailed().into())
        }
    }
}
