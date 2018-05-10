use std::mem;
use std::cmp;

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
