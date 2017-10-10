use std;
use std::ascii::AsciiExt;
use std::collections::HashMap;

//use ascii::Ascii;
//use ascii::AsciiCast;

static REF_FREQS: [(u8, f32); 28] = [
    (b' ', 12.17),
    (b'.', 6.57),
    (b'a', 6.09),
    (b'b', 1.05),
    (b'c', 2.84),
    (b'd', 2.92),
    (b'e', 11.36),
    (b'f', 1.79),
    (b'g', 1.38),
    (b'h', 3.41),
    (b'i', 5.44),
    (b'j', 0.24),
    (b'k', 0.41),
    (b'l', 2.92),
    (b'm', 2.76),
    (b'n', 5.44),
    (b'o', 6.00),
    (b'p', 1.95),
    (b'q', 0.24),
    (b'r', 4.95),
    (b's', 5.68),
    (b't', 8.03),
    (b'u', 2.43),
    (b'v', 0.97),
    (b'w', 1.38),
    (b'x', 0.24),
    (b'y', 1.30),
    (b'z', 0.03),
];

pub fn compute_score(v: &[u8]) -> u32 {
    if !v.is_ascii() {
        return std::u32::MAX;
    }

    if v.iter().any(|&c| is_control(c) && c != b'\n') {
        return std::u32::MAX;
    }

    let freqs = get_character_frequencies(v);

    let length = v.len() as f32;
    REF_FREQS.iter().fold(0f32, |a, &(c, score)| {
        let ref_count = score / 100f32 * length;
        let &obs_count = freqs.get(&c).unwrap_or(&0f32);
        a + (ref_count - obs_count).powi(2)
    }) as u32
}

fn is_control(u: u8) -> bool {
    u < 0x20 || u == 0x7F
}

fn is_alphabetic(u: u8) -> bool {
    (u >= 0x41 && u <= 0x5A) || (u >= 0x61 && u <= 0x7A)
}

fn get_character_frequencies(v: &[u8]) -> HashMap<u8, f32> {
    let mut freqs: HashMap<u8, f32> = HashMap::new();
    for &c in v.iter() {
        if is_control(c) {
            continue;
        }
        let key = if is_alphabetic(c) {
            c.to_ascii_lowercase()
        } else if c == b' ' || c == b'\t' {
            b' '
        } else {
            b'.'
        };

        let freq = freqs.entry(key).or_insert(0f32);
        *freq += 1f32;
    }
    freqs
}

pub fn ceil_div(n: usize, k: usize) -> (usize, usize) {
    let q = (n + k - 1) / k;
    let r = q * k - n;
    (q, r)
}
