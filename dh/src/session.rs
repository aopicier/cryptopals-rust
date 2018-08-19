use communication::Communicate;
use communication::CommunicateEncr;

use handshake::Handshake;

use failure::Error;

pub struct Session<T: Communicate> {
    stream: T,
    key: Vec<u8>,
}

impl<T: Communicate> Session<T> {
    pub fn new<U: Handshake<T>>(mut stream: T) -> Result<Session<T>, Error> {
        U::handshake(&mut stream).map(|key| Session { stream, key })
    }

    pub fn stream(&self) -> &T {
        &self.stream
    }
}

impl<T: Communicate> Communicate for Session<T> {
    fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        self.stream.send_encr(message, &self.key)
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.stream.receive_encr(&self.key)
    }
}
