use aes::BLOCK_SIZE;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use crate::errors::*;

fn contains_duplicates<T>(i: T) -> bool
where
    T: Iterator,
    <T as Iterator>::Item: Ord,
{
    let mut v: Vec<_> = i.collect();
    let len = v.len();
    v.sort();
    v.dedup();
    len != v.len()
}

pub fn run() -> Result<()> {
    let path = Path::new("data/8.txt");
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    // Find the line with a repeating 16 byte block.
    // The content of `file` is hex encoded. A byte block of length 16 therefore corresponds to a
    // character block of length 32.
    let result = reader
        .lines()
        .map(|line| line.unwrap())
        .find(|line| contains_duplicates(line.as_bytes().chunks(2 * BLOCK_SIZE)));

    compare_eq(
        Some(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5\
             d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649\
             af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c\
             7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6\
             aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd2\
             83d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c\
             58386b06fba186a"
                .to_owned(),
        ),
        result,
    )
}
