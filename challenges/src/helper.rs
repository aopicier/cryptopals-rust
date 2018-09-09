pub fn ceil_div(n: usize, k: usize) -> (usize, usize) {
    let q = (n + k - 1) / k;
    let r = q * k - n;
    (q, r)
}
