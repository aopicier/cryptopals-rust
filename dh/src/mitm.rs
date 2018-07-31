use algo::{secret_to_key, serialize};

use communication::decrypt;
use communication::Communicate;

use bignum::BigNumTrait;
use bignum::NumBigUint as BigNum;

use failure::Error;

pub struct MITM<T: Communicate> {
    client_stream: T,
    server_stream: T,
    client_key: Option<Vec<u8>>,
    server_key: Option<Vec<u8>>,
}

pub enum Mode {
    PublicKey,
    Generator,
}

impl<T: Communicate> MITM<T> {
    pub fn new(mut client_stream: T, mut server_stream: T, mode: Mode) -> Result<MITM<T>, Error> {
        let (client_key, server_key) = match mode {
            Mode::PublicKey => handshake_publickey(&mut client_stream, &mut server_stream)?,
            Mode::Generator => {
                handshake_generator(&mut client_stream, &mut server_stream, &BigNum::one())?
            }
        };
        Ok(MITM {
            client_stream,
            server_stream,
            client_key,
            server_key,
        })
    }

    pub fn send_server(&mut self, message: &[u8]) {
        self.server_stream.send(message).unwrap();
    }

    pub fn send_client(&mut self, message: &[u8]) {
        self.client_stream.send(message).unwrap();
    }

    pub fn receive_server(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.server_stream.receive()
    }

    pub fn receive_client(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.client_stream.receive()
    }

    pub fn decrypt_client(&self, message: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .client_key
            .as_ref()
            .map(|key| decrypt(message, key).unwrap()))
    }

    pub fn decrypt_server(&self, message: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .server_key
            .as_ref()
            .map(|key| decrypt(message, key).unwrap()))
    }
}

fn handshake_publickey<T: Communicate>(
    client_stream: &mut T,
    server_stream: &mut T,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), Error> {
    let p = client_stream.receive()?.unwrap();
    let g = client_stream.receive()?.unwrap();
    server_stream.send(&p)?;
    server_stream.send(&g)?;
    //Discard actual public keys
    client_stream.receive()?;
    server_stream.receive()?;
    //Send fake public keys
    client_stream.send(&p)?;
    server_stream.send(&p)?;
    let key = secret_to_key(&[0]);
    Ok((Some(key.clone()), Some(key)))
}

#[allow(non_snake_case)]
fn handshake_generator<T: Communicate>(
    client_stream: &mut T,
    server_stream: &mut T,
    g: &BigNum,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), Error> {
    let p = client_stream.receive()?.unwrap();
    client_stream.receive()?; //Discard g
    server_stream.send(&p)?;
    server_stream.send(&serialize(g))?;
    //Discard actual public keys
    let A = client_stream.receive()?.unwrap();
    let B = server_stream.receive()?.unwrap();
    //Send fake public keys
    client_stream.send(&B)?;
    server_stream.send(&A)?;
    Ok((Some(secret_to_key(&serialize(g))), None))
}
