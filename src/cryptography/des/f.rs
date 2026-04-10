use crate::cryptography::des::{e_box::e_box, s_box::s_box};

/// DES Feistel Function (F)
///
/// Applies the DES round function to a 32-bit block using a 48-bit subkey.
///
/// The function performs the following steps:
///
/// 1. Expansion permutation (E-box) — 32 bits → 48 bits
/// 2. XOR with round subkey
/// 3. Substitution using S-boxes — 48 bits → 32 bits
///
/// # Arguments
///
/// * `bits` - 32-bit right half of the block
/// * `k` - 48-bit round subkey (stored in `u64`)
///
/// # Returns
///
/// A 32-bit transformed block
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::f::f;
///
/// let right: u32 = 0x12345678;
/// let key: u64 = 0x3A94D63F2C1E;
///
/// let result = f(right, key);
///
/// assert!(result <= 0xFFFFFFFF);
/// ```
///
/// # Notes
///
/// - This function is used inside each DES round
/// - The output is XORed with the left half in the Feistel structure
/// - Only the lower 48 bits of `k` are used
///
/// # DES Round Structure
///
/// ```text
/// Lᵢ₊₁ = Rᵢ
/// Rᵢ₊₁ = Lᵢ XOR F(Rᵢ, Kᵢ)
/// ```
///
/// # See also
///
/// - `e_box()`
/// - `s_box()`
/// - `round()`
pub fn f(bits: u32, k: u64) -> u32 {
    let expanded: u64 = e_box(bits);
    let xor = expanded ^ k;
    let sbox: u32 = s_box(xor);
    sbox
}
