use algo::DH;

use communication::Communicate;
use communication::CommunicateEncr;

use failure::{Error, err_msg};

use bignum::NumBigUint as BigNum;

pub struct ServerSession<T: Communicate> {
    stream: T,
    key: Vec<u8>,
}

impl<T: Communicate> ServerSession<T> {
    pub fn new(mut stream: T) -> Result<ServerSession<T>, Error> {
        handshake(&mut stream).map(|key| ServerSession { stream, key })
    }
}

impl<T: Communicate> Communicate for ServerSession<T> {
    fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        self.stream.send_encr(message, &self.key)
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.stream.receive_encr(&self.key)
    }
}

#[allow(non_snake_case)]
fn handshake<T: Communicate>(stream: &mut T) -> Result<Vec<u8>, Error> {
    let p = stream.receive()?.ok_or_else(|| err_msg("did not receive p"))?;
    let g = stream.receive()?.ok_or_else(|| err_msg("did not receive g"))?;
    let dh = DH::<BigNum>::new_with_parameters(p, g);
    let B = dh.public_key();
    stream.send(&B)?;
    let A = stream.receive()?.ok_or_else(|| err_msg("did not receive A"))?;;
    Ok(dh.shared_key(&A))
}
