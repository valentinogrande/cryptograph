use crate::math::{bezout::bezout, euclides::gcd};

/// Computes the multiplicative inverse of `a` modulo `m`, if it exists.
///
/// The inverse is the integer `x` in `[0, m)` such that:
///
/// ```text
/// a · x ≡ 1 (mod m)
/// ```
///
/// Returns `None` if `gcd(a, m) != 1`, since the inverse only exists
/// when `a` and `m` are coprime.
///
/// # Examples
/// ```
/// use cryptograph::math::multiplicative_inverse::multiplicative_inverse;
/// assert_eq!(multiplicative_inverse(3, 7), Some(5));  // 3·5 = 15 ≡ 1 (mod 7)
/// assert_eq!(multiplicative_inverse(78, 30), None);   // gcd(78, 30) = 6
/// ```
pub fn multiplicative_inverse(a: i32, m: i32) -> Option<i32> {
    if gcd(a, m) != 1 {
        return None;
    }

    let s = bezout(a, m).0;

    Some(((s % m) + m) % m)
}
