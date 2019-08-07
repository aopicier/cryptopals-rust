use xor::XOR;

use crate::set2::prefix_length;

use crate::errors::*;

use crate::prefix_suffix_oracles::{Oracle, Oracle26};

pub fn run() -> Result<()> {
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
