pub fn ceil_quotient(n: usize, k: usize) -> (usize, usize) {
    assert!(k > 0);
    let q = (n + k - 1) / k;
    let r = q * k - n;
    (q, r)
}
