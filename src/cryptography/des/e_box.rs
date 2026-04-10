const E_BOX: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// DES Expansion Permutation (E-box)
///
/// Expands a 32-bit input into a 48-bit output using the DES expansion
/// permutation table.
///
/// This function is used inside the DES F-function to:
///
/// - Expand 32-bit right half
/// - Duplicate boundary bits
/// - Prepare for XOR with round key
///
/// # Overview
///
/// The expansion follows the DES E-box permutation:
///
/// - Input: 32 bits
/// - Output: 48 bits
/// - Some bits are duplicated
///
/// # Arguments
///
/// * `bits` - 32-bit right half block
///
/// # Returns
///
/// A 48-bit expanded value stored in `u64`
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::e_box::e_box;
///
/// let input: u32 = 0x12345678;
/// let expanded = e_box(input);
///
/// assert!(expanded <= 0xFFFFFFFFFFFF);
/// ```
///
/// # Notes
///
/// - Output uses only lower 48 bits
/// - Used before XOR with round key
/// - Part of DES F-function
///
/// # See also
///
/// - `f()`
/// - `SBOXES`
/// - `permutation`
pub fn e_box(bits: u32) -> u64 {
    let mut expanded: u64 = 0;
    for (i, pos) in E_BOX.iter().enumerate() {
        let bit = (bits >> (pos - 1)) & 1;
        expanded |= ((bit) as u64) << i;
    }
    expanded
}
