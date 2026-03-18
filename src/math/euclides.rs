use std::ops::{Div, Mul, Rem, Sub};

use num_traits::Zero;

/// Computes the greatest common divisor (GCD) of `a` and `b`
/// using the Euclidean algorithm.
///
/// # Panics
/// Panics if `b == 0`.
///
/// # Examples
/// ```
///use cryptograph::math::euclides::gcd;
///
/// assert_eq!(gcd(48, 18), 6);
/// assert_eq!(gcd(17, 43), 1);
/// ```
pub fn gcd<T>(a: T, b: T) -> T
where
    T: Copy
        + PartialEq
        + Zero
        + Div<Output = T>
        + Mul<Output = T>
        + Rem<Output = T>
        + Sub<Output = T>,
{
    if a % b != T::zero() { gcd(b, a % b) } else { b }
}
