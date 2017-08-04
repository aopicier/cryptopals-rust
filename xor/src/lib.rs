pub trait XOR {
    fn xor(&self, &Self) -> Vec<u8>;
    fn xor_inplace(&mut self, &Self);
}

impl XOR for [u8] {
    fn xor(&self, t: &[u8]) -> Vec<u8> {
        let mut result = self.to_vec();
        &mut result[..].xor_inplace(t);
        result
    }

    fn xor_inplace(&mut self, t: &[u8]) {
        for chunk in self.chunks_mut(t.len()) {
            let len = chunk.len();
            for (c, &d) in chunk.iter_mut().zip(t[..len].iter()) {
                *c ^= d;
            }
        }
    }
}
