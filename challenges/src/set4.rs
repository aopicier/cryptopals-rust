use std::path::Path;
use std::ascii::AsciiExt;
use std::mem;

use byteorder::{ByteOrder, BigEndian};

use aes::Aes128;
use aes::BLOCK_SIZE;
use aes::MODE;

use xor::XOR;

use serialize::from_base64_file;
use serialize::from_hex;

use mac::mac_sha1;
use mac::hmac_sha1;

use hmac_client;
use hmac_server;

use rand;
use rand::Rng;

use sha1::Sha1;

use unstable_features::MoveFrom;

use set2::decode_profile;
use set2::oracle_generator;
use set2::prefix_length;
use set2::random_block;

use errors::*;

fn edit4_25(ciphertext: &[u8], key: &[u8], offset: usize, newtext: Vec<u8>) -> Result<Vec<u8>> {
    let mut cleartext = ciphertext.decrypt(key, None, MODE::CTR)?;
    let n = newtext.len();
    cleartext[offset..].move_from2(newtext, 0, n);
    cleartext.encrypt(key, None, MODE::CTR).map_err(|x| x.into())
}

fn matasano4_25() -> Result<()> {
    let cleartext = from_base64_file(Path::new("data/25.txt"))?;
    let key = random_block();
    let ciphertext = cleartext.encrypt(&key, None, MODE::CTR)?;
    let keystream = edit4_25(&ciphertext, &key, 0, vec![0; ciphertext.len()])?;
    compare(cleartext, ciphertext.xor(&keystream))
}

fn matasano4_26() -> Result<()> {
    let key = random_block();
    let oracle = |input: &[u8]| {
        // Exclude ';' and '='
        if input.iter().any(|&c| !c.is_ascii() || c == b';' || c == b'=') {
            panic!("Invalid input.");
        }

        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        oracle_generator(&key, prefix, input, suffix, MODE::CTR)
    };

    // This exercise is trivial: In CTR mode, if we know the underlying plaintext at some location, 
    // we can inject any plaintext at the same location by xor'ing the ciphertext with 
    // known_plaintext ^ target_plaintext.

    let prefix_len = prefix_length(&oracle)?;
    let target_cleartext = b";admin=true";
    let mut ciphertext = oracle(&vec![0; target_cleartext.len()])?;
    ciphertext.truncate(prefix_len + target_cleartext.len());
    ciphertext[prefix_len..].xor_inplace(target_cleartext);
    compare(Some(b"true".as_ref()), decode_profile(&ciphertext.decrypt(&key, None, MODE::CTR)?, b';').remove(b"admin".as_ref()))
}

fn setup4_27() -> (Box<Fn(&[u8]) -> Result<Vec<u8>>>,
                   Box<Fn(&[u8]) -> Result<()>>,
                   Box<Fn(&[u8]) -> bool>) {
    let secret_key = random_block();

    let key = secret_key.clone();
    let encrypter = move |input: &[u8]| {
        // Exclude ';' and '='
        if input.iter().any(|&c| !c.is_ascii() || c == b';' || c == b'=') {
            bail!("invalid character in input");
        }

        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        let mut cleartext = Vec::with_capacity(prefix.len() + input.len() + suffix.len());
        cleartext.extend_from_slice(prefix);
        cleartext.extend_from_slice(input);
        cleartext.extend_from_slice(suffix);
        cleartext.encrypt(&key, Some(&key), MODE::CBC).map_err(|err| err.into())
    };

    let key = secret_key.clone();
    let receiver = move |ciphertext: &[u8]| {
        let cleartext = ciphertext.decrypt(&key, Some(&key), MODE::CBC)?;
        if !cleartext.is_ascii() {
            return Err(ErrorKind::NonAscii(cleartext).into());
        }
        Ok(())
    };

    let key = secret_key.clone();
    let validator = move |candidate_key: &[u8]| {
        key == candidate_key
    };

    (Box::new(encrypter), Box::new(receiver), Box::new(validator))
}

fn matasano4_27() -> Result<()> {
    let (encrypter, receiver, validator) = setup4_27();

    let ciphertext = encrypter(&[])?;

    let mut attack_ciphertext = Vec::with_capacity(3*BLOCK_SIZE);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&[0; BLOCK_SIZE]);
    attack_ciphertext.extend_from_slice(&ciphertext[0..BLOCK_SIZE]);
    //Push last two blocks to preserve valid padding at the end
    attack_ciphertext.extend_from_slice(&ciphertext[ciphertext.len()-2*BLOCK_SIZE..]);

    if let Err(Error(ErrorKind::NonAscii(attack_cleartext), _)) = receiver(&attack_ciphertext) {
        compare(true, validator(&attack_cleartext[0..BLOCK_SIZE].xor(&attack_cleartext[2*BLOCK_SIZE..3*BLOCK_SIZE])))
    } else {
        bail!("attack ciphertext did not deceive the receiver");
    }
}

fn matasano4_28() -> Result<()> {
    compare(from_hex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")?, mac_sha1(b"The quick brown fox ", b"jumps over the lazy dog"))
}

fn setup4_29() ->  (Box<Fn(&[u8]) -> Vec<u8>>,
                   Box<Fn(&[u8], &[u8]) -> bool>) {
    let mut rng = rand::thread_rng();
    let key_len = rng.gen_range(1, 200);
    let secret_key: Vec<u8> = rng.gen_iter().take(key_len).collect();

    let key = secret_key.clone();
    let compute_mac = move |message: &[u8]| mac_sha1(&key, message);

    let key = secret_key.clone();
    let verify_mac = move |message: &[u8], mac: &[u8]| &mac_sha1(&key, message)[..] == mac;
    (Box::new(compute_mac), Box::new(verify_mac))
}

fn padding(length: usize) -> Vec<u8> {
    let mut w = Vec::<u8>::with_capacity(137);
    w.extend_from_slice(&[0x80u8]);
    let padding = 64 - ((length + 9) % 64);
    for _ in 0..padding {
        w.push(0u8);
    }
    w.extend_from_slice(unsafe { &mem::transmute::<_, [u8; 8]>((((length as u64) % 64 + (length as u64)/64*64) * 8).to_be()) });
    w
}

fn matasano4_29() -> Result<()> {
    let input = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let suffix = b";admin=true";

    let (compute_mac, verify_mac) = setup4_29();
    let hash = compute_mac(input);

    let mut state: [u32; 5] = [0; 5];
    for (b, s) in hash.chunks(4).zip(state.iter_mut()) {
        //Transmute four u8 values to u32

        *s = <BigEndian as ByteOrder>::read_u32(b)
    }

    for key_len in 0..200 {
        let secret_len = input.len() + key_len;
        let padding = padding(secret_len);
        let mut m2 = Sha1::new_with_state_and_length(state, (secret_len + padding.len()) as u64);
        m2.update(suffix);
        let mac = m2.digest();

        let mut message = Vec::new();
        message.extend_from_slice(input);
        message.extend_from_slice(&padding);
        message.extend_from_slice(suffix);
        if verify_mac(&message, &mac) {
            return Ok(());
        }
    }
    bail!("No matching message found.");
}

fn matasano4_30() -> Result<()> {
    /* Skipping/postponing Challenge 30 because 
     * 1) SHA1 was much more interesting anyway, 
     * 2) no MD4 implementation seems to be available.  */

    bail!(ErrorKind::NotImplemented);
}

fn matasano4_31() -> Result<()> {
    compare(from_hex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")?, hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog"))
}


fn matasano4_32() -> Result<()> {
    let skip_exercise = true;

    if skip_exercise {
        bail!("Skipping for performance reasons");
    }

    let mut rng = rand::thread_rng();
    let key: Vec<u8> = rng.gen_iter().take(20).collect();

    let mut server = hmac_server::start(key);

    hmac_client::run();

    server.close().chain_err(|| "failed to close connection")?;

    Ok(()) //TODO Add proper error handling
}

pub fn run() {
    println!("Set 4");

    run_exercise(matasano4_25, 25);
    run_exercise(matasano4_26, 26);
    run_exercise(matasano4_27, 27);
    run_exercise(matasano4_28, 28);
    run_exercise(matasano4_29, 29);
    run_exercise(matasano4_30, 30);
    run_exercise(matasano4_31, 31);
    run_exercise(matasano4_32, 32);
}
