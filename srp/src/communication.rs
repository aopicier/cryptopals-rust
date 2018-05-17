use byteorder::{ByteOrder, LittleEndian};

use std::io::{Read, Write};

use failure::Error;

// Share with DH?

pub trait Communicate {
    fn send(&mut self, message: &[u8]) -> Result<(), Error>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error>;
}

fn message_length<T: Read>(stream: &mut T) -> Result<Option<usize>, Error> {
    Ok(read_n_bytes(stream, 4)?.as_ref().map(|message| {
        <LittleEndian as ByteOrder>::read_u32(message) as usize
    }))
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
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(message_length(self)?.and_then(|length| read_n_bytes(self, length).unwrap()))
    }

    fn send(&mut self, message: &[u8]) -> Result<(), Error> {
        let length = encode_length(message.len());
        self.write(&length)?;
        self.write(message)?;
        Ok(())
    }
}
