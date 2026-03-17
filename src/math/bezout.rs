/// Computes the Bézout coefficients `(s, t)` for `a` and `b` using the
/// extended Euclidean algorithm, such that:
///
/// ```text
/// a·s + b·t = gcd(a, b)
/// ```
///
/// # Returns
/// A tuple `(s, t)` where `s` is the coefficient for `a` and `t` for `b`.
///
/// # Examples
/// ```
///use cryptograph::math::bezout::bezout;
///
/// let (s, t) = bezout(17, 43);
/// assert_eq!(17 * s + 43 * t, 1);
/// ```
pub fn bezout(a: i32, b: i32) -> (i32, i32) {
    if b == 0 {
        return (1, 0);
    }

    let (x1, y1) = bezout(b, a % b);

    (y1, x1 - (a / b) * y1)
}
