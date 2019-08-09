use rand;
use rand::Rng;

use aes;
use aes::{Aes128, MODE};

use byteorder::{ByteOrder, LittleEndian};
use result::ResultOptionExt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

use std::io::{Read, Write};

pub trait Communicate {
    fn send(&mut self, message: &[u8]) -> Result<()>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>>;
}

pub trait CommunicateNew {
    fn send(&self, message: &[u8]) -> Result<()>;
    fn receive(&self) -> Result<Option<Vec<u8>>>;
}

pub trait CommunicateEncr: Communicate {
    fn receive_encr(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.receive()?
            .as_ref()
            .map(|message| decrypt(message, key))
            .invert()
    }

    fn send_encr(&mut self, message: &[u8], key: &[u8]) -> Result<()> {
        let mut rng = rand::thread_rng();
        let iv: Vec<u8> = rng.gen_iter().take(aes::BLOCK_SIZE).collect();
        let mut message_encr = message.encrypt(key, Some(&iv), MODE::CBC)?;
        message_encr.extend_from_slice(&iv);
        self.send(&message_encr)
    }
}

pub fn decrypt(message: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut msg = message.to_vec();
    let len = msg.len();
    let iv = msg.split_off(len - aes::BLOCK_SIZE);
    msg.decrypt(key, Some(&iv), MODE::CBC)
        .map_err(|err| err.into())
}

fn message_length<T: Read>(stream: &mut T) -> Result<Option<usize>> {
    Ok(read_n_bytes(stream, 4)?
        .as_ref()
        .map(|message| <LittleEndian as ByteOrder>::read_u32(message) as usize))
}

fn encode_length(length: usize) -> Vec<u8> {
    let mut buf = vec![0; 4];
    <LittleEndian as ByteOrder>::write_u32(&mut buf, length as u32);
    buf
}

fn read_n_bytes<T: Read>(stream: &mut T, n: usize) -> Result<Option<Vec<u8>>> {
    let mut reader: Vec<u8> = Vec::with_capacity(n);
    let buf = &mut vec![0; n];
    let mut l = buf.len();
    while l != 0 {
        let k = stream.read(buf)?;
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
    fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        message_length(self)?
            .and_then(|length| read_n_bytes(self, length).invert())
            .invert()
    }

    fn send(&mut self, message: &[u8]) -> Result<()> {
        let length = encode_length(message.len());
        self.write_all(&length)?;
        self.write_all(message)?;
        Ok(())
    }
}

impl<T: Communicate> CommunicateEncr for T {}
