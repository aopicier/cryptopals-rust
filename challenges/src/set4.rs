use std::path::Path;

use aes::Aes128;
use aes::BLOCK_SIZE;
use aes::MODE;

use xor::XOR;

use serialize::from_base64_file;
use serialize::from_hex;

use mac::hmac_sha1;
use mac::mac_sha1;

use hmac_client;
use hmac_server;

use rand;
use rand::Rng;

use set2::prefix_length;
use set2::random_block;

use errors::*;

use prefix_suffix_oracles::{Oracle, Oracle26};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use sha1::Sha1;
use std::mem;

struct Encrypter25 {
    cleartext: Vec<u8>,
    key: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Encrypter25 {
    pub fn new() -> Result<Self, Error> {
        let cleartext = from_base64_file(Path::new("data/25.txt"))?;
        let key = random_block();
        let ciphertext = cleartext.encrypt(&key, None, MODE::CTR)?;
        Ok(Encrypter25 {
            cleartext,
            key,
            ciphertext,
        })
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn edit(&self, offset: usize, newtext: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut cleartext = self.cleartext.clone();
        let end = offset + newtext.len();
        if end > cleartext.len() {
            bail!("input out of bounds")
        }
        cleartext[offset..end].copy_from_slice(&newtext);
        cleartext.encrypt(&self.key, None, MODE::CTR)
    }

    pub fn verify_solution(&self, candidate_cleartext: &[u8]) -> Result<(), Error> {
        compare_eq(&self.cleartext[..], candidate_cleartext)
    }
}

fn challenge_25() -> Result<(), Error> {
    // This exercise is trivial: In CTR mode, if we know the underlying plaintext at some location,
    // we can trivially recover the used keystream by xor'ing the ciphertext with the
    // known plaintext. We simply use the edit function to set the entire cleartext to 0 so that
    // the ciphertext is even equal to the keystream.

    let encrypter = Encrypter25::new()?;
    let ciphertext = encrypter.get_ciphertext();
    let keystream = encrypter.edit(0, vec![0; ciphertext.len()])?;
    encrypter.verify_solution(&ciphertext.xor(&keystream))
}

fn challenge_26() -> Result<(), Error> {
    // This exercise is trivial: In CTR mode, if we know the underlying plaintext at some location,
    // we can inject any plaintext at the same location by xor'ing the ciphertext with
    // known_plaintext ^ target_plaintext.

    let oracle = Oracle26::new()?;
    let prefix_len = prefix_length(&oracle)?;
    let target_cleartext = b";admin=true";
    let mut ciphertext = oracle.encrypt(&vec![0; target_cleartext.len()])?;
    ciphertext.truncate(prefix_len + target_cleartext.len());
    ciphertext[prefix_len..].xor_inplace(target_cleartext);
    oracle.verify_solution(&ciphertext)
}

struct Sender27 {
    key: Vec<u8>,
}

struct Receiver27 {
    key: Vec<u8>,
}

impl Sender27 {
    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        // Exclude ';' and '='
        if input
            .iter()
            .any(|&c| !c.is_ascii() || c == b';' || c == b'=')
        {
            bail!("invalid character in input");
        }

        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        let mut cleartext = Vec::with_capacity(prefix.len() + input.len() + suffix.len());
        cleartext.extend_from_slice(prefix);
        cleartext.extend_from_slice(input);
        cleartext.extend_from_slice(suffix);
        cleartext.encrypt(&self.key, Some(&self.key), MODE::CBC)
    }
}

impl Receiver27 {
    pub fn try_decrypt(&self, ciphertext: &[u8]) -> Result<(), Error> {
        let cleartext = ciphertext.decrypt(&self.key, Some(&self.key), MODE::CBC)?;
        if !cleartext.is_ascii() {
            Err(NonAscii(cleartext).into())
        } else {
            Ok(())
        }
    }

    pub fn verify_solution(&self, candidate_key: &[u8]) -> Result<(), Error> {
        compare_eq(&self.key[..], candidate_key)
    }
}

fn get_sender_and_receiver_with_shared_key() -> (Sender27, Receiver27) {
    let secret_key = random_block();
    let sender = Sender27 {
        key: secret_key.clone(),
    };
    let receiver = Receiver27 {
        key: secret_key.clone(),
    };
    (sender, receiver)
}

#[derive(Debug, Fail)]
#[fail(display = "invalid input: {:?}", _0)]
struct NonAscii(Vec<u8>);

fn challenge_27() -> Result<(), Error> {
    let (sender, receiver) = get_sender_and_receiver_with_shared_key();

    let ciphertext = sender.encrypt(&[])?;

    let mut attack_ciphertext = Vec::with_capacity(3 * BLOCK_SIZE);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&[0; BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);
    //Push last two blocks to preserve valid padding at the end
    attack_ciphertext.extend_from_slice(&ciphertext[ciphertext.len() - 2 * BLOCK_SIZE..]);

    if let Err(err) = receiver.try_decrypt(&attack_ciphertext) {
        if let Ok(NonAscii(attack_cleartext)) = err.downcast::<NonAscii>() {
            return receiver.verify_solution(
                &attack_cleartext[0..BLOCK_SIZE]
                    .xor(&attack_cleartext[2 * BLOCK_SIZE..3 * BLOCK_SIZE]),
            );
        }
    }

    bail!("attack ciphertext did not deceive the receiver");
}

fn challenge_28() -> Result<(), Error> {
    compare_eq(
        from_hex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")?,
        mac_sha1(b"The quick brown fox ", b"jumps over the lazy dog"),
    )
}

// Below we want to create an instance of the Sha1 type from the
// sha1 crate with a specific state. Unfortunately the sha1 crate
// does not offer any way to do this.
// We therfore include a copy of the Sha1 type here. We can then create
// an instance of our type with the desired state and transmute it to Sha1.

struct Sha1_0_20 {
    _state: Sha1State,
    _blocks: Blocks,
    _len: u64,
}

struct Blocks {
    _len: u32,
    _block: [u8; 64],
}

struct Sha1State {
    _state: [u32; 5],
}

impl Sha1_0_20 {
    fn new(state: [u32; 5], len: u64) -> Self {
        Sha1_0_20 {
            _state: Sha1State { _state: state },
            _len: len,
            _blocks: Blocks {
                _len: 0,
                _block: [0; 64],
            },
        }
    }
}

struct Server29 {
    key: Vec<u8>,
}

impl Server29 {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let key_len = rng.gen_range(1, 200);
        let key: Vec<u8> = rng.gen_iter().take(key_len).collect();
        Server29 { key }
    }

    pub fn get_message_with_mac(&self) -> (Vec<u8>, Vec<u8>) {
        let message =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
                .to_vec();
        let mac = mac_sha1(&self.key, &message);
        (message, mac)
    }

    pub fn verify_mac(&self, message: &[u8], mac: &[u8]) -> bool {
        mac_sha1(&self.key, message) == mac
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

fn padding(length: usize) -> Vec<u8> {
    let mut w = Vec::new();
    w.push(0x80u8);
    let zero_padding_length = 64 - ((length + 9) % 64);
    for _ in 0..zero_padding_length {
        w.push(0u8);
    }
    w.write_u64::<BigEndian>((length as u64) * 8).unwrap();
    w
}

fn challenge_29() -> Result<(), Error> {
    let server = Server29::new();
    let (original_message, mac) = server.get_message_with_mac();
    let new_message = b";admin=true";

    // Split the 20 bytes of `mac` into chunks of four
    // bytes and interpret each chunk as a u32.
    let mut state: [u32; 5] = [0; 5];
    for (b, s) in mac.chunks(4).zip(state.iter_mut()) {
        *s = BigEndian::read_u32(b)
    }

    // We do not know the actual key length so we have to try different possibilities.
    for key_len in 0..200 {
        let secret_len = original_message.len() + key_len;
        let padding = padding(secret_len);
        let mut m2: Sha1;
        unsafe {
            m2 = mem::transmute(Sha1_0_20::new(state, (secret_len + padding.len()) as u64));
        }
        m2.update(new_message);
        let mac = m2.digest().bytes();

        let mut message = Vec::new();
        message.extend_from_slice(&original_message);
        message.extend_from_slice(&padding);
        message.extend_from_slice(new_message);
        if server.verify_mac(&message, &mac) {
            return Ok(());
        }
    }
    bail!("No matching message found.");
}

fn challenge_30() -> Result<(), Error> {
    /* Skipping/postponing Challenge 30 because
     * 1) SHA1 was much more interesting anyway,
     * 2) no MD4 implementation seems to be available.  */

    Err(ChallengeError::NotImplemented.into())
}

fn challenge_31() -> Result<(), Error> {
    compare_eq(
        from_hex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")?,
        hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog"),
    )
}

fn challenge_32() -> Result<(), Error> {
    let skip_exercise = true;

    if skip_exercise {
        return Err(ChallengeError::Skipped("Runs very long.").into());
    }

    let mut rng = rand::thread_rng();
    let key: Vec<u8> = rng.gen_iter().take(20).collect();

    let mut server = hmac_server::start(key);

    hmac_client::run();

    server.close().context("failed to close connection")?;

    Ok(()) //TODO Add proper error handling
}

pub fn add_challenges(challenges: &mut Vec<fn() -> Result<(), Error>>) {
    challenges.push(challenge_25);
    challenges.push(challenge_26);
    challenges.push(challenge_27);
    challenges.push(challenge_28);
    challenges.push(challenge_29);
    challenges.push(challenge_30);
    challenges.push(challenge_31);
    challenges.push(challenge_32);
}
