/// DES Initial Permutation column mapping.
///
/// Used to compute the initial permutation without
/// explicitly storing the full IP table.
const PERMUTATION_TABLE: [u8; 8] = [2, 4, 6, 8, 1, 3, 5, 7];

/// DES Final Permutation (IP⁻¹) table.
///
/// This is the inverse of the initial permutation.
const FINAL_PERMUTATION: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// Applies the DES Initial Permutation (IP).
///
/// Rearranges the 64-bit input block before the
/// Feistel rounds.
///
/// # Arguments
///
/// * `x` - 64-bit plaintext block
///
/// # Returns
///
/// Permuted 64-bit block
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::permutation::initial_permutation;
///
/// let input = 0x0123456789ABCDEF;
/// let permuted = initial_permutation(input);
///
/// assert!(permuted <= u64::MAX);
/// ```
///
/// # Notes
///
/// - This permutation is reversed by `final_permutation`
/// - Required by DES specification
pub fn initial_permutation(x: u64) -> u64 {
    let mut permuted: u64 = 0;
    for bit in 0..64 {
        let column = PERMUTATION_TABLE
            .iter()
            .position(|r| *r == (bit % 8) + 1u8)
            .unwrap();

        let row = bit / 8;

        let index = (column * 8) as u8 + row.abs_diff(7);
        let bit_val = (x >> bit) & 1;

        permuted |= bit_val << index;
    }
    permuted
}

/// Applies the DES Final Permutation (IP⁻¹).
///
/// Reverses the initial permutation after the
/// 16 Feistel rounds.
///
/// # Arguments
///
/// * `x` - 64-bit block after Feistel rounds
///
/// # Returns
///
/// Final encrypted 64-bit block
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::permutation::final_permutation;
///
/// let block = 0x0123456789ABCDEF;
/// let result = final_permutation(block);
///
/// assert!(result <= u64::MAX);
/// ```
///
/// # Notes
///
/// - Inverse of `initial_permutation`
/// - Last step of DES encryption
pub fn final_permutation(x: u64) -> u64 {
    let mut unpermutated_message: u64 = 0;

    for (i, pos) in FINAL_PERMUTATION.iter().enumerate() {
        let bit = (x >> (pos - 1)) & 1;
        unpermutated_message |= bit << i;
    }

    unpermutated_message
}
