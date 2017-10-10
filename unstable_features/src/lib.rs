use std::mem;
use std::cmp;

pub fn all_bytes() -> Vec<u8> {
    (0..std::u8::MAX as u32 + 1).map(|u| u as u8).collect()
}

pub trait MoveFrom<T> {
    fn move_from2(&mut self, src: Vec<T>, start: usize, end: usize) -> usize;
}

impl<T> MoveFrom<T> for [T] {
    fn move_from2(&mut self, mut src: Vec<T>, start: usize, end: usize) -> usize {
        for (a, b) in self.iter_mut().zip(src[start..end].iter_mut()) {
            mem::swap(a, b);
        }
        cmp::min(self.len(), end - start)
    }
}
