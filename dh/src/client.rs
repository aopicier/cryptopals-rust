use algo::DH;

use communication::Communicate;
use communication::CommunicateEncr;

use bignum::NumBigUint as BigNum;

use errors::*;

pub struct Client<T: Communicate> {
    stream: T,
    key: Vec<u8>,
}

impl<T: Communicate> Client<T> {
    pub fn new(mut stream: T) -> Result<Client<T>> {
        handshake(&mut stream).map(|key| {
            Client {
                stream: stream,
                key: key,
            }
        })
    }

    pub fn stream(&self) -> &T {
        &self.stream
    }
}

impl<T: Communicate> Communicate for Client<T> {
    fn send(&mut self, message: &[u8]) -> Result<()> {
        self.stream.send_encr(message, &self.key)
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        self.stream.receive_encr(&self.key)
    }
}

#[allow(non_snake_case)]
fn handshake<T: Communicate>(stream: &mut T) -> Result<Vec<u8>> {
    let mut dh = DH::<BigNum>::new();
    dh.init();
    let (p, g) = dh.parameters();
    stream.send(&p)?;
    stream.send(&g)?;
    let A = dh.public_key();
    stream.send(&A)?;
    let B = stream.receive()?.unwrap();
    Ok(dh.shared_key(&B))
}
