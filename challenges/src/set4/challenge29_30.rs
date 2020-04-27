use mac::{mac_md4, mac_sha1};

use rand::Rng;

use crate::errors::*;

use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use md4::{Digest, Md4};
use sha1::Sha1;
use std::marker::PhantomData;
use std::mem;

use crate::simd::u32x4;
use block_buffer::BlockBuffer512;

// Below we want to create an instance of the Sha1 type from the
// sha1 crate with a specific state. Unfortunately the sha1 crate
// does not offer any way to do this.
// We therfore include a copy of the Sha1 type here. We can then create
// an instance of our type with the desired state and transmute it to Sha1.

struct Sha1_0_7_0 {
    _state: [u32; 5],
    _len: u64,
    _buffer: BlockBuffer512,
}

impl Sha1_0_7_0 {
    fn new(state: &[u32], len: u64) -> Self {
        assert_eq!(5, state.len());
        Sha1_0_7_0 {
            _state: [state[0], state[1], state[2], state[3], state[4]],
            _len: len,
            _buffer: BlockBuffer512::default(),
        }
    }
}

struct MacServer<T: MacHelper> {
    key: Vec<u8>,
    phantom: PhantomData<T>,
}

impl<T: MacHelper> MacServer<T> {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let key_len = rng.gen_range(1, 200);
        let key: Vec<u8> = rng.gen_iter().take(key_len).collect();
        Self {
            key,
            phantom: PhantomData,
        }
    }

    pub fn get_message_with_mac(&self) -> (Vec<u8>, Vec<u8>) {
        let message =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
                .to_vec();
        let mac = T::compute_mac(&self.key, &message);
        (message, mac)
    }

    pub fn verify_mac(&self, message: &[u8], mac: &[u8]) -> bool {
        T::compute_mac(&self.key, message) == mac
    }
}

/* A SHA-1 hasher consists of an internal state of 160 bits and a function which takes 512
 * bits of data and mangles them with the current state to produce a new state. In order to compute
 * the hash of a message, the message is first padded with the padding function below so that
 * its length is a multiple of 512 bits. It is then split into chunks of 512 bits and the chunks
 * are consecutively passed to the mangling function (starting with a hardcoded initial state).
 * The resulting state is the hash of the message.
 *
 * In other words, SHA1(message) = state after processing (message || padding)
 *
 * Hence if we use SHA1(message) as the initial state of a hasher and then use
 * this hasher to compute the hash of another-message, the resulting hash will be equal to
 * SHA1(message || padding || another-message)
 *
 * This observation is the basis for the following challenge.
 */

fn padding<T: ByteOrder>(length: usize) -> Vec<u8> {
    let mut w = Vec::new();
    w.push(0x80u8);
    let zero_padding_length = 64 - ((length + 9) % 64);
    for _ in 0..zero_padding_length {
        w.push(0u8);
    }
    w.write_u64::<T>((length as u64) * 8).unwrap();
    w
}

trait MacHelper {
    fn compute_mac(message: &[u8], key: &[u8]) -> Vec<u8>;
    fn hash_to_state(hash: &[u8]) -> Vec<u32>;
    fn padding(length: usize) -> Vec<u8>;
    fn get_forged_mac(state: &[u32], len: usize, new_message: &[u8]) -> Vec<u8>;
}

struct Sha1Helper;

impl MacHelper for Sha1Helper {
    fn compute_mac(message: &[u8], key: &[u8]) -> Vec<u8> {
        mac_sha1(message, key)
    }

    fn hash_to_state(hash: &[u8]) -> Vec<u32> {
        hash.chunks(4).map(|b| BigEndian::read_u32(b)).collect()
    }

    fn padding(length: usize) -> Vec<u8> {
        padding::<BigEndian>(length)
    }

    fn get_forged_mac(state: &[u32], len: usize, new_message: &[u8]) -> Vec<u8> {
        let mut m2: Sha1;
        unsafe {
            m2 = mem::transmute(Sha1_0_7_0::new(&state, len as u64));
        }
        m2.input(new_message);
        m2.result().to_vec()
    }
}

struct Md4Helper;

impl MacHelper for Md4Helper {
    fn compute_mac(message: &[u8], key: &[u8]) -> Vec<u8> {
        mac_md4(message, key)
    }

    fn hash_to_state(hash: &[u8]) -> Vec<u32> {
        hash.chunks(4).map(|b| LittleEndian::read_u32(b)).collect()
    }

    fn padding(length: usize) -> Vec<u8> {
        padding::<LittleEndian>(length)
    }

    fn get_forged_mac(state: &[u32], len: usize, new_message: &[u8]) -> Vec<u8> {
        let mut m2: Md4;
        unsafe {
            m2 = mem::transmute(Md4_0_7_0::new(&state, len as u64));
        }
        m2.input(new_message);
        m2.result().to_vec()
    }
}

fn run_29_30<T: MacHelper>() -> Result<()> {
    let server = MacServer::<T>::new();
    let (original_message, mac) = server.get_message_with_mac();
    let new_message = b";admin=true";

    // Split the 20 bytes of `mac` into chunks of four
    // bytes and interpret each chunk as a u32.
    //let state: Vec<u32> = mac.chunks(4).map(|b| BigEndian::read_u32(b)).collect();
    let state: Vec<u32> = T::hash_to_state(&mac);

    // We do not know the actual key length so we have to try different possibilities.
    for key_len in 0..200 {
        let secret_len = original_message.len() + key_len;
        let padding = T::padding(secret_len);
        let mac = T::get_forged_mac(&state, secret_len + padding.len(), new_message);

        let mut message = Vec::new();
        message.extend_from_slice(&original_message);
        message.extend_from_slice(&padding);
        message.extend_from_slice(new_message);
        if server.verify_mac(&message, &mac) {
            return Ok(());
        }
    }
    Err("No matching message found.".into())
}

pub fn run29() -> Result<()> {
    run_29_30::<Sha1Helper>()
}

struct Md4_0_7_0 {
    _length_bytes: u64,
    _buffer: BlockBuffer512,
    _state: Md4State,
}

struct Md4State {
    _s: u32x4,
}

impl Md4_0_7_0 {
    fn new(state: &[u32], len: u64) -> Self {
        assert_eq!(4, state.len());
        Md4_0_7_0 {
            _state: Md4State {
                _s: u32x4(state[0], state[1], state[2], state[3]),
            },
            _length_bytes: len,
            _buffer: BlockBuffer512::default(),
        }
    }
}

pub fn run30() -> Result<()> {
    run_29_30::<Md4Helper>()
}
