#[macro_use]
extern crate error_chain;

use std::char;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::path::Path;

error_chain! {
    errors { }

    foreign_links {
        Io(::std::io::Error) #[cfg(unix)];
    }
}

pub trait Serialize {
    fn to_base64(&self) -> String;
    fn to_hex(&self) -> String;
}

impl Serialize for [u8] {
    fn to_base64(&self) -> String {
        let mut base64 = String::with_capacity(4 * self.len() / 3);
        for block in self.chunks(3) {
            block_to_base64(block, &mut base64);
        }

        if self.len() % 3 >= 1 {
            base64.pop();
            if self.len() % 3 == 1 {
                base64.pop();
                base64.push('=');
            }
            base64.push('=');
        }

        base64
    }

    fn to_hex(&self) -> String {
        let mut u4 = Vec::with_capacity(2 * self.len());
        for u in self {
            u4.push(u >> 4);
            u4.push(u & 0xf);
        }
        u4.iter()
            .map(|&u| char::from_digit(u as u32, 16).unwrap())
            .collect()
    }
}

pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    if s.len() % 4 != 0 {
        bail!("input length needs to be multiple of 4");
    }

    let mut n = s.len();
    if s.as_bytes()[n - 1] == b'=' {
        if s.as_bytes()[n - 2] == b'=' {
            n -= 1;
        }
        n -= 1;
    }

    let mut digits = Vec::with_capacity(n);
    for c in s.chars().take(n) {
        digits.push(u8_from_base64(c).chain_err(|| format!("not a valid base64 string: {}", s))?);
    }

    let mut u = Vec::with_capacity(3 * s.len() / 4);
    for b in digits.chunks(4) {
        u.push((b[0] << 2) + (b[1] >> 4));
        if b.len() == 2 {
            if b[1] << 4 != 0 {
                bail!("input not padded with zero");
            }
            break;
        }

        u.push((b[1] << 4) + (b[2] >> 2));
        if b.len() == 3 {
            if b[2] << 6 != 0 {
                bail!("input not padded with zero");
            }
            break;
        }

        u.push((b[2] << 6) + b[3]);
    }
    Ok(u)
}

pub fn from_base64_file(path: &Path) -> Result<Vec<u8>> {
    let mut content = String::new();
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        content.push_str(line.unwrap().trim());
    }
    from_base64(&content)
}

pub fn from_base64_lines(path: &Path) -> Result<Vec<Vec<u8>>> {
    from_lines(path, from_base64)
}

pub fn from_hex_lines(path: &Path) -> Result<Vec<Vec<u8>>> {
    from_lines(path, from_hex)
}

fn from_lines(path: &Path, converter: fn(&str) -> Result<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    let mut content = Vec::new();
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        content.push(converter(line.unwrap().trim())?);
    }
    Ok(content)
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("input length needs to be multiple of 2");
    }

    let mut digits = Vec::with_capacity(s.len());
    for c in s.chars() {
        digits.push(u8_from_hex(c)
            .chain_err(|| format!("not a valid hex string: {}", s))?);
    }
    Ok(
        digits
            .chunks(2)
            .map(|c| (c[0] << 4) + c[1])
            .collect::<Vec<u8>>(),
    )
}

fn u8_from_hex(c: char) -> Result<u8> {
    match c.to_digit(16) {
        Some(i) => Ok(i as u8),
        _ => bail!(format!("invalid character {}", c)),
    }
}

fn block_to_base64(block: &[u8], base64: &mut String) {
    let (a, b, c) = match block.len() {
        3 => (block[0], block[1], block[2]),
        2 => (block[0], block[1], 0),
        1 => (block[0], 0, 0),
        _ => return,
    };
    base64.push(u8_to_base64(a >> 2)); // Upper 6 bits of a
    base64.push(u8_to_base64(a % 4 * 16 + (b >> 4))); // Lower 2 bits of a, upper 4 bits of b
    base64.push(u8_to_base64(b % 16 * 4 + (c >> 6))); // Lower 4 bits of b, upper 2 bits of c
    base64.push(u8_to_base64(c & 0x3f)); // Lower 6 bits of c
}

fn u8_to_base64(u: u8) -> char {
    match u {
        0...25 => ('A' as u8 + u) as char,
        26...51 => ('a' as u8 + (u - 26)) as char,
        52...61 => ('0' as u8 + (u - 52)) as char,
        62 => '+',
        63 => '/',
        _ => panic!("input exceeded range"),
    }
}

fn u8_from_base64(c: char) -> Result<u8> {
    match c {
        'A'...'Z' => Ok(c as u8 - 'A' as u8),
        'a'...'z' => Ok(26 + (c as u8 - 'a' as u8)),
        '0'...'9' => Ok(52 + (c as u8 - '0' as u8)),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => bail!(format!("invalid character {}", c)),
    }
}
