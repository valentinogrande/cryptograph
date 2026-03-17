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
pub fn gcd(a: i32, b: i32) -> i32 {
    if a % b != 0 { gcd(b, a % b) } else { b }
}
