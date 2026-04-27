//! Helpers for the AES `SubBytes` step.
//!
//! AES builds its substitution box in two stages:
//!
//! 1. Compute the multiplicative inverse of each byte in `GF(2^8)`.
//! 2. Apply the fixed AES affine transformation.
//!
//! This module exposes both the standard AES S-box and the helper functions
//! used to regenerate it for educational purposes.
//!
//! # Example
//!
//! ```rust
//! use cryptograph::cryptography::aes::bite_sub::{affine_mapping, generate_inverse_table, SBOX};
//!
//! let generated = affine_mapping(generate_inverse_table());
//! assert_eq!(generated, SBOX);
//! ```
use gf256::gf;

#[gf(polynomial = 0x11b, generator = 0x3)]
pub type Gf256Rijndael;

/// Standard AES S-box indexed by high nibble and low nibble.
///
/// `SBOX[high][low]` returns the substituted byte for the input `0x{high}{low}`.
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::aes::bite_sub::SBOX;
///
/// assert_eq!(SBOX[0x0][0x0], 0x63);
/// assert_eq!(SBOX[0x5][0x3], 0xed);
/// assert_eq!(SBOX[0xf][0xf], 0x16);
/// ```
pub const SBOX: [[u8; 16]; 16] = [
    [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
    ],
    [
        202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
    ],
    [
        183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
    ],
    [
        4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
    ],
    [
        9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
    ],
    [
        83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
    ],
    [
        208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
    ],
    [
        81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
    ],
    [
        205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
    ],
    [
        96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
    ],
    [
        224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
    ],
    [
        231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
    ],
    [
        186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
    ],
    [
        112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
    ],
    [
        225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
    ],
    [
        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
    ],
];

/// Generates the multiplicative inverse table used by AES before the affine step.
///
/// The value at position `[high][low]` corresponds to the multiplicative inverse
/// of byte `0x{high}{low}` in `GF(2^8)`. AES keeps `0x00` mapped to `0x00`
/// before applying the affine transformation.
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::aes::bite_sub::generate_inverse_table;
///
/// let inverse = generate_inverse_table();
///
/// assert_eq!(inverse[0x0][0x0], 0x00);
/// assert_eq!(inverse[0x0][0x1], 0x01);
/// assert_eq!(inverse[0x5][0x3], 0xca);
/// ```
pub fn generate_inverse_table() -> [[u8; 16]; 16] {
    let mut init = [[0; 16]; 16];
    for i in 0..16 {
        for j in 0..16 {
            let value = (i * 16 + j) as u8;
            if value == 0 {
            } else {
                let inverse_polynomio = Gf256Rijndael::new(value).recip().0;
                init[i][j] = inverse_polynomio;
            }
        }
    }

    init
}

/// Generates the bit-rotation masks used by the AES affine transformation.
///
/// The returned array stores the rotated versions of the base mask `0x1f` used
/// to compute each output bit during `SubBytes`.
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::aes::bite_sub::generate_affine_mapping_table;
///
/// let table = generate_affine_mapping_table();
///
/// assert_eq!(table, [0x3e, 0x7c, 0xf8, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f]);
/// ```
pub fn generate_affine_mapping_table() -> [u8; 8] {
    let mut init: u8 = 0b00011111;
    let mut table: [u8; 8] = [0; 8];
    for i in 0..8 {
        init = init.rotate_left(1);
        table[i] = init;
    }
    table
}

/// Applies the AES affine transformation to an inverse table.
///
/// When called with the inverse table produced by [`generate_inverse_table`],
/// this function reconstructs the standard AES S-box.
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::aes::bite_sub::{affine_mapping, generate_inverse_table, SBOX};
///
/// let inverse = generate_inverse_table();
/// let sbox = affine_mapping(inverse);
///
/// assert_eq!(sbox, SBOX);
/// ```
pub fn affine_mapping(inverse: [[u8; 16]; 16]) -> [[u8; 16]; 16] {
    let const_vector = 0x63;

    let mut final_table = [[0u8; 16]; 16];

    for i in 0..16 {
        for j in 0..16 {
            let val = inverse[i][j];
            final_table[i][j] = val
                ^ val.rotate_left(1)
                ^ val.rotate_left(2)
                ^ val.rotate_left(3)
                ^ val.rotate_left(4)
                ^ const_vector;
        }
    }

    final_table
}

#[cfg(test)]
mod tests {
    use super::{SBOX, affine_mapping, generate_affine_mapping_table, generate_inverse_table};

    #[test]
    fn inverse_table_contains_known_values() {
        let inverse = generate_inverse_table();

        assert_eq!(inverse[0x0][0x0], 0x00);
        assert_eq!(inverse[0x0][0x1], 0x01);
        assert_eq!(inverse[0x5][0x3], 0xCA);
        assert_eq!(inverse[0xC][0xA], 0x53);
    }

    #[test]
    fn affine_mapping_table_matches_expected_rotations() {
        assert_eq!(
            generate_affine_mapping_table(),
            [0x3E, 0x7C, 0xF8, 0xF1, 0xE3, 0xC7, 0x8F, 0x1F]
        );
    }

    #[test]
    fn affine_mapping_recreates_standard_aes_sbox() {
        let inverse = generate_inverse_table();
        let generated_sbox = affine_mapping(inverse);

        assert_eq!(generated_sbox, SBOX);
    }
}
