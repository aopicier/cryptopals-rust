use algo::DH;

use communication::Communicate;
use communication::CommunicateEncr;

use bignum::NumBigUint as BigNum;

use failure::Error;

pub struct ClientSession<T: Communicate> {
    stream: T,
    key: Vec<u8>,
}

impl<T: Communicate> ClientSession<T> {
    pub fn new(mut stream: T) -> Result<ClientSession<T>, Error> {
        handshake(&mut stream).map(|key| ClientSession { stream, key })
    }

    pub fn stream(&self) -> &T {
        &self.stream
    }
}

impl<T: Communicate> Communicate for ClientSession<T> {
    fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        self.stream.send_encr(message, &self.key)
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.stream.receive_encr(&self.key)
    }
}

#[allow(non_snake_case)]
fn handshake<T: Communicate>(stream: &mut T) -> Result<Vec<u8>, Error> {
    let mut dh = DH::<BigNum>::new();
    // TODO Remove init method
    dh.init();
    let (p, g) = dh.parameters();
    stream.send(&p)?;
    stream.send(&g)?;
    let A = dh.public_key();
    stream.send(&A)?;
    let B = stream.receive()?.unwrap();
    Ok(dh.shared_key(&B))
}
