pub mod cryptoanalysis;
pub mod cryptography;
pub mod math;

#[cfg(test)]
mod tests {
    use crate::math::{
        bezout::bezout, euclides::gcd, multiplicative_inverse::multiplicative_inverse,
    };

    #[test]
    fn euclides_test() {
        assert_eq!(gcd(78, 30), 6)
    }
    #[test]
    fn bezout_test() {
        assert_eq!(bezout(78, 30), (2, -5));
    }
    #[test]
    fn multiplicative_inverse_test() {
        assert_eq!(multiplicative_inverse(3, 7), Some(5))
    }
}
