use std::ops::{Div, Mul, Rem, Sub};

use num_traits::{One, Zero};

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
pub fn multiplicative_inverse<T>(a: T, m: T) -> Option<T>
where
    T: Copy
        + PartialEq
        + Zero
        + One
        + Div<Output = T>
        + Mul<Output = T>
        + Rem<Output = T>
        + Sub<Output = T>,
{
    if gcd(a, m) != T::one() {
        return None;
    }

    let s = bezout(a, m).0;

    Some(((s % m) + m) % m)
}
