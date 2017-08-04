extern crate sha1;
extern crate xor;

use sha1::Sha1;

use xor::XOR;

fn sha1(data: &[u8]) -> Vec<u8> {
    let mut m = Sha1::new();
    m.update(data);
    m.digest()
}

pub fn mac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(key.len() + message.len());
    data.extend_from_slice(key);
    data.extend_from_slice(message);

    sha1(&data)
}

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = prepare_key(key, 64);

    let mut i_key_pad = key.xor(&[0x36]);
    i_key_pad.extend_from_slice(message);

    let mut o_key_pad = key.xor(&[0x5c]);
    o_key_pad.extend_from_slice(&sha1(&i_key_pad));

    sha1(&o_key_pad)
}

fn prepare_key(key: &[u8], block_size: usize) -> Vec<u8> {
    let mut key = if key.len() > block_size {
        sha1(&key)
    } else {
        key.to_vec()
    };

    while key.len() < block_size {
        key.push(0);
    }
    key
}
