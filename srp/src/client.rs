use crate::algo::{
    deserialize, hash_secret, serialize, zero, BigNum, ClientHandshake, DefaultUComputer,
    LoginResult, UComputer, SRP,
};

use std::error;
use std::fmt;

use crate::communication::Communicate;
use std::marker::PhantomData;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Debug, Clone)]
struct LoginFailed();

// This is important for other errors to wrap this one.
impl error::Error for LoginFailed {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl fmt::Display for LoginFailed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "server rejected login")
    }
}

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

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<()> {
        stream.send(&self.user_name)?;
        stream.send(&self.password)?;
        Ok(())
    }

    fn login<T: Communicate>(&self, stream: &mut T) -> Result<()> {
        stream.send(&self.user_name)?;
        let state = ClientHandshake::new(&self.params);
        let A = state.A();
        stream.send(&serialize(A))?;
        let salt: Vec<u8> = stream.receive()?.ok_or_else(|| "salt")?;
        let B = deserialize(&stream.receive()?.ok_or_else(|| "B")?);
        let u = U::compute_u(&A, &B, stream)?;
        let secret = state.compute_hashed_secret(&B, &u, &salt, &self.password);
        stream.send(&secret)?;
        let login_result = stream.receive()?.ok_or_else(|| "login result")?;
        if login_result == [LoginResult::Success as u8] {
            Ok(())
        } else {
            Err(LoginFailed().into())
        }
    }
}

struct SimplifiedUComputer;

impl UComputer for SimplifiedUComputer {
    fn compute_u<T: Communicate>(_: &BigNum, _: &BigNum, stream: &mut T) -> Result<BigNum> {
        let u_raw = stream.receive()?.ok_or_else(|| "u")?;
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

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<()> {
        self.base.register(stream)
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<()> {
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

    pub fn register<T: Communicate>(&self, stream: &mut T) -> Result<()> {
        self.base.register(stream)
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<()> {
        self.base.login(stream)
    }
}

pub struct FakeClientWithZeroKey {
    user_name: Vec<u8>,
}

#[allow(clippy::just_underscores_and_digits)]
impl FakeClientWithZeroKey {
    pub fn new(user_name: Vec<u8>) -> Self {
        FakeClientWithZeroKey { user_name }
    }

    pub fn login<T: Communicate>(&self, stream: &mut T) -> Result<()> {
        stream.send(&self.user_name)?;
        let _0 = zero();

        // Send zero for A
        stream.send(&serialize(&_0))?;

        let salt: Vec<u8> = stream.receive()?.ok_or_else(|| "salt")?;

        // Discard B
        stream.receive()?.ok_or_else(|| "B")?;

        // If A is zero, the S computed by the server is also zero.
        // The following hashed secret will therefore fool the server.
        let secret = hash_secret(&_0, &salt);
        stream.send(&secret)?;

        let login_result = stream.receive()?.ok_or_else(|| "login result")?;

        if login_result == [LoginResult::Success as u8] {
            Ok(())
        } else {
            Err(LoginFailed().into())
        }
    }
}
