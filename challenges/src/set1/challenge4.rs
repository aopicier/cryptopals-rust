use errors::*;
use serialize::from_hex_lines;
use set1::challenge3::compute_score;
use std::path::Path;
use xor::XOR;

pub fn run() -> Result<(), Error> {
    let path = Path::new("data/4.txt");
    let lines = from_hex_lines(path)?;
    let result = lines
        .into_iter()
        .flat_map(|line: Vec<u8>| (0u8..128).map(move |u| line.xor(&[u])))
        .min_by_key(|cand| compute_score(cand))
        .unwrap(); // unwrap is ok

    compare_eq(b"Now that the party is jumping\n".as_ref(), &result)
}
