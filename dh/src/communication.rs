use rand;
use rand::Rng;

use aes;
use aes::{Aes128, MODE};

use byteorder::{ByteOrder, LittleEndian};
use result::ResultOptionExt;

use std::io::{Read, Write};

use failure::{Error, ResultExt};

pub trait Communicate {
    fn send(&mut self, message: &[u8]) -> Result<(), Error>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error>;
}

pub trait CommunicateNew {
    fn send(&self, message: &[u8]) -> Result<(), Error>;
    fn receive(&self) -> Result<Option<Vec<u8>>, Error>;
}

pub trait CommunicateEncr: Communicate {
    fn receive_encr(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.receive()?
            .as_ref()
            .map(|message| decrypt(message, key))
            .invert()
    }

    fn send_encr(&mut self, message: &[u8], key: &[u8]) -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let iv: Vec<u8> = rng.gen_iter().take(aes::BLOCK_SIZE).collect();
        let mut message_encr = message.encrypt(key, Some(&iv), MODE::CBC)?;
        message_encr.extend_from_slice(&iv);
        self.send(&message_encr)
    }
}

pub fn decrypt(message: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut msg = message.to_vec();
    let len = msg.len();
    let iv = msg.split_off(len - aes::BLOCK_SIZE);
    msg.decrypt(key, Some(&iv), MODE::CBC)
}

fn message_length<T: Read>(stream: &mut T) -> Result<Option<usize>, Error> {
    Ok(read_n_bytes(stream, 4)?
        .as_ref()
        .map(|message| <LittleEndian as ByteOrder>::read_u32(message) as usize))
}

fn encode_length(length: usize) -> Vec<u8> {
    let mut buf = vec![0; 4];
    <LittleEndian as ByteOrder>::write_u32(&mut buf, length as u32);
    buf
}

fn read_n_bytes<T: Read>(stream: &mut T, n: usize) -> Result<Option<Vec<u8>>, Error> {
    let mut reader: Vec<u8> = Vec::with_capacity(n);
    let buf = &mut vec![0; n];
    let mut l = buf.len();
    while l != 0 {
        let k = stream.read(buf).context("failed to read from stream")?;
        if k == 0 {
            return Ok(None);
        }
        reader.extend_from_slice(&buf[..k]);
        l -= k;
        buf.truncate(l);
    }
    Ok(Some(reader))
}

impl<T: Read + Write> Communicate for T {
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        message_length(self)?
            .and_then(|length| read_n_bytes(self, length).invert())
            .invert()
    }

    fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        let length = encode_length(message.len());
        self.write(&length).context("failed to write to stream")?;
        self.write(message).context("failed to write to stream")?;
        Ok(())
    }
}

impl<T: Communicate> CommunicateEncr for T {}
