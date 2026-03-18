use num_traits::{One, Zero};
use std::ops::{Div, Mul, Rem, Sub};

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
pub fn bezout<T>(a: T, b: T) -> (T, T)
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
    if b == T::zero() {
        return (T::one(), T::zero());
    }

    let (x1, y1) = bezout(b, a % b);

    (y1, x1 - (a / b) * y1)
}
