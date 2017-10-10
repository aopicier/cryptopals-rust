use std::ops::Range;
pub const STATE_SIZE: usize = 624;


// The following code is a direct translation of the pseudocode found on Wikipedia

/*
 // Create a length 624 array to store the state of the generator
 int[0..623] MT
 int index = 0
*/

pub struct MersenneTwister {
    mt: [u32; STATE_SIZE],
    index: usize,
}

impl MersenneTwister {
    /* 
     // Initialize the generator from a seed
     function initialize_generator(int seed) {
         index := 0
         MT[0] := seed
         for i from 1 to 623 { // loop over each element
             MT[i] := lowest 32 bits of(1812433253 * (MT[i-1] xor (right shift by 30 bits(MT[i-1]))) + i) // 0x6c078965
         }
     }
    */

    pub fn initialize(seed: u32) -> Self {
        let mut mt = [0; STATE_SIZE];
        mt[0] = seed;
        for i in 1..STATE_SIZE {
            mt[i] = (mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_mul(0x6c07_8965)
                .wrapping_add(i as u32);
        }
        MersenneTwister { mt: mt, index: 0 }
    }

    /*
     // Generate an array of 624 untempered numbers
     function generate_numbers() {
         for i from 0 to 623 {
             int y := (MT[i] and 0x80000000)                       // bit 31 (32nd bit) of MT[i]
                            + (MT[(i+1) mod 624] and 0x7fffffff)   // bits 0-30 (first 31 bits) of MT[...]
             MT[i] := MT[(i + 397) mod 624] xor (right shift by 1 bit(y))
             if (y mod 2) != 0 { // y is odd
                 MT[i] := MT[i] xor (2567483615) // 0x9908b0df
             }
         }
     }
    */

    fn generate(&mut self) {
        for i in 0..STATE_SIZE {
            let mt = &mut self.mt;
            let y = (mt[i] & 0x8000_0000) | (mt[(i + 1) % STATE_SIZE] & 0x7fff_ffff);
            mt[i] = mt[(i + 397) % STATE_SIZE] ^ (y >> 1);
            if y % 2 != 0 {
                mt[i] ^= 0x9908_b0df;
            }
        }
    }

    pub fn initialize_with_state(mt: [u32; STATE_SIZE]) -> MersenneTwister {
        MersenneTwister { mt: mt, index: 0 }
    }
}

impl Iterator for MersenneTwister {
    type Item = u32;
    /*
     // Extract a tempered pseudorandom number based on the index-th value,
     // calling generate_numbers() every 624 numbers
     function extract_number() {
         if index == 0 {
             generate_numbers()
         }
     
         int y := MT[index]
         y := y xor (right shift by 11 bits(y))
         y := y xor (left shift by 7 bits(y) and (2636928640)) // 0x9d2c5680
         y := y xor (left shift by 15 bits(y) and (4022730752)) // 0xefc60000
         y := y xor (right shift by 18 bits(y))

         index := (index + 1) mod 624
         return y
     }
     
    */

    fn next(&mut self) -> Option<u32> {
        if self.index == 0 {
            self.generate();
        }
        let y = temper(self.mt[self.index]);
        self.index = (self.index + 1) % STATE_SIZE;
        Some(y)
    }
}

fn temper(mut y: u32) -> u32 {
    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c_5680;
    y ^= (y << 15) & 0xefc6_0000;
    y ^= y >> 18;
    y
}

fn inv_rs(mut u: u32, k: u32) -> u32 {
    assert!(k >= 1);
    let mut v = u;
    //Would profit from range_inclusive and std::u32::BITS
    for _ in 0..32 / k + 1 {
        u >>= k;
        v ^= u;
    }
    v
}

fn inv_lsa(u: u32, k: u32, c: u32) -> u32 {
    assert!(k >= 1);
    let mut v = u;
    //Would profit from std::u32::BITS
    for _ in 0..32 / k {
        v = u ^ (v << k & c);
    }
    v
}

pub fn untemper(u: u32) -> u32 {
    inv_rs(
        inv_lsa(inv_lsa(inv_rs(u, 18), 15, 0xefc6_0000), 7, 0x9d2c_5680),
        11,
    )
}

pub fn crack_seed_from_nth(u: u32, n: usize, range: Range<u32>) -> Option<u32> {
    //Unfortunately we use brute force here. Is there an analytic attack?
    for candidate in range {
        if u == MersenneTwister::initialize(candidate).nth(n).unwrap() {
            return Some(candidate);
        }
    }
    None
}
