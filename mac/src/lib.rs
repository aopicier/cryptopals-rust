extern crate digest;
extern crate sha1;
extern crate sha2;
extern crate xor;

use digest::Digest;

use xor::XOR;

pub fn mac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(key.len() + message.len());
    data.extend_from_slice(key);
    data.extend_from_slice(message);

    sha1::Sha1::digest(&data).to_vec()
}

fn hmac<D: Digest>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = prepare_key::<D>(key);

    let mut i_key_pad = key.xor(&[0x36]);
    i_key_pad.extend_from_slice(message);

    let mut o_key_pad = key.xor(&[0x5c]);
    o_key_pad.extend_from_slice(&D::digest(&i_key_pad));

    D::digest(&o_key_pad).to_vec()
}

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<sha1::Sha1>(key, message)
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<sha2::Sha256>(key, message)
}

// This function assumes that the block size of D is 64.
// This is correct for SHA-1 and SHA-256.
fn prepare_key<D: Digest>(key: &[u8]) -> Vec<u8> {
    // TODO Somehow use <D as BlockInput>::BlockSize to obtain
    // the actual block size.
    let block_size = 64;
    let mut key = if key.len() > block_size {
        D::digest(key).to_vec()
    } else {
        key.to_vec()
    };

    while key.len() < block_size {
        key.push(0);
    }
    key
}
