//! Bit manipulation utilities.
//!
//! This module handles conversions between bit-level and byte-level
//! representations, commonly used in cryptographic and encoding contexts.

use std::error::Error;

/// Converts a slice of bits (`&[bool]`) into a vector of bytes (`Vec<u8>`).
///
/// Each group of 8 bits is interpreted as a single byte in **MSB → LSB** order.
///
/// # Arguments
///
/// * `bits` - Slice of boolean values:
///   - `true` = 1
///   - `false` = 0
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Reconstructed bytes.
/// * `Err(Box<dyn Error>)` - If length is not a multiple of 8.
///
/// # Example
///
/// ```
/// use cryptograph::bits::bits_to_bytes;
/// let bits = vec![true, false, true, false, false, false, false, true];
///
/// let bytes = bits_to_bytes(&bits).unwrap();
///
/// assert_eq!(bytes, vec![0b10100001]);
/// ```
///
/// # Notes
///
/// - Big-endian bit order inside each byte (MSB first).
/// - Uses bitwise ops: `<<` and `|`.
pub fn bits_to_bytes(bits: &[bool]) -> Result<Vec<u8>, Box<dyn Error>> {
    if !bits.len().is_multiple_of(8) {
        return Err("bits length must be multiple of 8".into());
    }

    let mut bytes = Vec::with_capacity(bits.len() / 8);

    for chunk in bits.chunks(8) {
        let mut byte = 0u8;

        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - i);
            }
        }

        bytes.push(byte);
    }

    Ok(bytes)
}

/// Converts a slice of bytes (`&[u8]`) into a vector of bits (`Vec<bool>`).
///
/// Each byte is expanded into 8 bits in **MSB → LSB** order.
///
/// # Arguments
///
/// * `bytes` - Slice of bytes.
///
/// # Returns
///
/// * `Vec<bool>` - Bits extracted from all bytes.
///
/// # Example
///
/// ```
/// use cryptograph::bits::bytes_to_bits;
///
/// let bytes = vec![0b10100001];
///
/// let bits = bytes_to_bits(&bytes);
///
/// assert_eq!(
///     bits,
///     vec![true, false, true, false, false, false, false, true]
/// );
/// ```
///
/// # Notes
///
/// - Big-endian bit order (MSB first).
/// - Uses bitwise ops: `>>` and `&`.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);

    for &byte in bytes {
        for i in (0..8).rev() {
            bits.push(((byte >> i) & 1) == 1);
        }
    }

    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_to_bytes_basic() {
        let bits = vec![
            true, false, true, false, false, false, false, true, // 10100001
        ];

        let bytes = bits_to_bytes(&bits).unwrap();

        assert_eq!(bytes, vec![0b10100001]);
    }

    #[test]
    fn test_bytes_to_bits_basic() {
        let bytes = vec![0b10100001];

        let bits = bytes_to_bits(&bytes);

        assert_eq!(
            bits,
            vec![true, false, true, false, false, false, false, true]
        );
    }

    #[test]
    fn test_roundtrip() {
        let original = vec![0b10100001, 0b11110000, 0b00001111];

        let bits = bytes_to_bits(&original);
        let reconstructed = bits_to_bytes(&bits).unwrap();

        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_invalid_length() {
        let bits = vec![true, false, true]; // no múltiplo de 8

        let result = bits_to_bytes(&bits);

        assert!(result.is_err());
    }
}
