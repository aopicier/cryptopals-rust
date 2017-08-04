use rand;
use rand::Rng;

use aes;
use aes::{Aes128, MODE};

use byteorder::{ByteOrder, LittleEndian};

use std::io::{Read, Write};

use errors::*;

pub trait Communicate {
    fn send(&mut self, message: &[u8]) -> Result<()>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>>;
}

pub trait CommunicateEncr: Communicate {
    fn receive_encr(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.receive()?.map(|message| decrypt(message, key).unwrap()))
    }

    fn send_encr(&mut self, message: &[u8], key: &[u8]) -> Result<()> {
        let mut rng = rand::thread_rng();
        let iv: Vec<u8> = rng.gen_iter().take(aes::BLOCK_SIZE).collect();
        let mut message_encr = message.encrypt(key, Some(&iv), MODE::CBC).unwrap();
        message_encr.extend_from_slice(&iv);
        self.send(&message_encr)
    }
}

pub fn decrypt(mut message: Vec<u8>, key: &[u8]) -> Result<Vec<u8>> {
    let len = message.len();
    let iv = message.split_off(len - aes::BLOCK_SIZE);
    message.decrypt(key, Some(&iv), MODE::CBC).map_err(|err| err.into())
}

fn message_length<T: Read>(stream: &mut T) -> Result<Option<usize>> {
    Ok(read_n_bytes(stream, 4)?.as_ref().map(|message| <LittleEndian as ByteOrder>::read_u32(message) as usize))
}

fn encode_length(length: usize) -> Vec<u8> {
    let mut buf = vec![0; 4];
    <LittleEndian as ByteOrder>::write_u32(&mut buf, length as u32);
    buf
}

fn read_n_bytes<T: Read>(stream: &mut T, n: usize) -> Result<Option<Vec<u8>>> {
    let mut reader: Vec<u8> = Vec::with_capacity(n);
    let mut buf = &mut vec![0; n];
    let mut l = buf.len();
    while l != 0 {
        let k = stream.read(buf).chain_err(|| "failed to read from stream")?;
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
        Ok(message_length(self)?.and_then(|length| read_n_bytes(self, length).unwrap()))
    }

    fn send(&mut self, message: &[u8]) -> Result<()> {
        let length = encode_length(message.len());
        self.write(&length).chain_err(|| "failed to write to stream")?;
        self.write(message).chain_err(|| "failed to write to stream")?;
        Ok(())
    }
}

impl<T: Communicate> CommunicateEncr for T {}
