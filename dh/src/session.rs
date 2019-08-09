use crate::communication::Communicate;
use crate::communication::CommunicateEncr;

use crate::handshake::Handshake;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub struct Session<T: Communicate> {
    stream: T,
    key: Vec<u8>,
}

impl<T: Communicate> Session<T> {
    pub fn new<U: Handshake<T>>(mut stream: T) -> Result<Session<T>> {
        U::handshake(&mut stream).map(|key| Session { stream, key })
    }

    pub fn stream(&self) -> &T {
        &self.stream
    }
}

impl<T: Communicate> Communicate for Session<T> {
    fn send(&mut self, message: &[u8]) -> Result<()> {
        self.stream.send_encr(message, &self.key)
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        self.stream.receive_encr(&self.key)
    }
}
