/// DES Permuted Choice 1 (PC-1) table.
///
/// Reduces the 64-bit key to 56 bits by removing parity bits
/// and permuting the remaining bits.
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// DES Permuted Choice 2 (PC-2) table.
///
/// Reduces the 56-bit key halves into a 48-bit round key.
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Rounds where only one left shift is performed.
///
/// DES shift schedule:
///
/// 1, 2, 9, 16 → 1 shift
/// others → 2 shifts
const ONE_SHIFT_ROUNDS: [u8; 4] = [1, 2, 9, 16];

/// Applies DES Permuted Choice 1 (PC-1).
///
/// Converts a 64-bit key into a 56-bit key by removing parity bits
/// and permuting the remaining bits.
///
/// # Arguments
///
/// * `key` - 64-bit DES key
///
/// # Returns
///
/// 56-bit permuted key stored in `u64`
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::key::permutated_choice_1;
///
/// let key = 0x133457799BBCDFF1;
/// let result = permutated_choice_1(key);
///
/// assert!(result <= 0x00FFFFFFFFFFFFFF);
/// ```
pub fn permutated_choice_1(key: u64) -> u64 {
    let mut permutated_key: u64 = 0;
    for (i, pos) in PC1.iter().enumerate() {
        let bit = (key >> (pos - 1)) & 1;
        permutated_key |= bit << (i as u64);
    }
    permutated_key
}

/// Applies DES Permuted Choice 2 (PC-2).
///
/// Combines left and right 28-bit halves and produces
/// a 48-bit round key.
///
/// # Arguments
///
/// * `left` - Left 28-bit key half
/// * `right` - Right 28-bit key half
///
/// # Returns
///
/// 48-bit round key stored in `u64`
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::key::permutated_choice_2;
///
/// let left = 0x0FFFFFFF;
/// let right = 0x0FFFFFFF;
///
/// let key = permutated_choice_2(left, right);
/// ```
pub fn permutated_choice_2(left: u32, right: u32) -> u64 {
    let key: u64 = (left as u64) << 28 | right as u64;

    let mut permutated_key: u64 = 0;

    for (i, pos) in PC2.iter().enumerate() {
        let bit = (key >> (pos - 1)) & 1;
        permutated_key |= bit << (i as u64);
    }

    permutated_key
}

/// Performs DES key schedule shifting.
///
/// Rotates both 28-bit key halves left according to
/// DES shift schedule.
///
/// # Arguments
///
/// * `left_key` - Left 28-bit key half
/// * `right_key` - Right 28-bit key half
/// * `n` - Current round number
///
/// # Returns
///
/// Tuple `(left, right)` shifted key halves
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::key::key_shift;
///
/// let left = 0x0FFFFFFF;
/// let right = 0x0FFFFFFF;
///
/// let (l, r) = key_shift(left, right, 1);
/// ```
pub fn key_shift(left_key: u32, right_key: u32, n: u8) -> (u32, u32) {
    if ONE_SHIFT_ROUNDS.contains(&n) {
        let lk = (left_key << 1 | left_key >> 27) & 0x0FFFFFFF;
        let rk = (right_key << 1 | right_key >> 27) & 0x0FFFFFFF;
        (lk, rk)
    } else {
        let lk = (left_key << 2 | left_key >> 26) & 0x0FFFFFFF;
        let rk = (right_key << 2 | right_key >> 26) & 0x0FFFFFFF;
        (lk, rk)
    }
}
