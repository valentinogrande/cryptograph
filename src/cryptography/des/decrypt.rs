use crate::cryptography::des::encrypt::Des;
use crate::cryptography::des::f::f;
use crate::cryptography::des::key::{
    inverse_key_shift, key_shift, permutated_choice_1, permutated_choice_2,
};
use crate::cryptography::des::permutation::{final_permutation, initial_permutation};

/// Performs one DES decryption round using the Feistel structure.
///
/// # Description
///
/// This function executes a single round of the DES decryption process.
/// It performs:
///
/// 1. Inverse key schedule shift
/// 2. Subkey generation (PC-2)
/// 3. Feistel transformation
///
/// The round transformation follows:
///
/// ```text
/// L_i = R_{i-1}
/// R_i = L_{i-1} XOR f(R_{i-1}, K_i)
/// ```
///
/// # Arguments
///
/// * `n` - Current round number (1..=16)
/// * `left_key` - Left half of key (28 bits)
/// * `right_key` - Right half of key (28 bits)
/// * `left_x` - Left half of data block (32 bits)
/// * `right_x` - Right half of data block (32 bits)
///
/// # Returns
///
/// Returns the updated `(left_x, right_x)` pair.
///
/// # Notes
///
/// This function modifies keys and data in-place for performance.
///
/// # DES Round Structure
///
/// ```text
///      ┌────────────┐
/// R ──►│     f      │
///      └─────┬──────┘
///            │
/// L ─────XOR─┘
///
/// swap(L, R)
/// ```
///
/// # Security
///
/// DES is considered insecure for modern cryptographic use.
/// This implementation is intended for educational purposes.
pub fn round(
    n: u8,
    left_key: &mut u32,
    right_key: &mut u32,
    left_x: &mut u32,
    right_x: &mut u32,
) -> (u32, u32) {
    (*left_key, *right_key) = inverse_key_shift(*left_key, *right_key, n);

    let key = permutated_choice_2(*left_key, *right_key);
    let temp = *right_x;

    *right_x = *left_x ^ f(*right_x, key);
    *left_x = temp;
    (*left_x, *right_x)
}

impl Des {
    /// Decrypts a 64-bit block using the DES algorithm.
    ///
    /// # Description
    ///
    /// This function performs DES decryption using:
    ///
    /// 1. Initial permutation (IP)
    /// 2. 16 Feistel rounds
    /// 3. Final swap
    /// 4. Final permutation (IP⁻¹)
    ///
    /// # DES Decryption Flow
    ///
    /// ```text
    /// Ciphertext
    ///     ↓
    /// Initial Permutation (IP)
    ///     ↓
    /// 16 Feistel rounds
    ///     ↓
    /// Swap (R16, L16)
    ///     ↓
    /// Final Permutation (IP⁻¹)
    ///     ↓
    /// Plaintext
    /// ```
    ///
    /// # Arguments
    ///
    /// * `y` - Ciphertext block (64 bits)
    /// * `key` - DES key (64 bits, including parity bits)
    ///
    /// # Returns
    ///
    /// Returns decrypted 64-bit plaintext.
    ///
    /// # Key Schedule
    ///
    /// The key schedule follows:
    ///
    /// 1. Permuted Choice 1 (PC-1)
    /// 2. 16 forward rotations to derive round keys
    /// 3. Permuted Choice 2 (PC-2), then reverse key order for decryption
    ///
    /// # Feistel Structure
    ///
    /// DES uses a Feistel network:
    ///
    /// ```text
    /// L_i = R_{i-1}
    /// R_i = L_{i-1} XOR f(R_{i-1}, K_i)
    /// ```
    ///
    /// # Performance
    ///
    /// This implementation:
    ///
    /// - avoids allocations
    /// - uses bitwise operations
    /// - operates entirely on registers
    ///
    /// # Security Warning
    ///
    /// DES is cryptographically broken and should not be used in production.
    ///
    /// Recommended alternatives:
    ///
    /// - AES-128
    /// - AES-256
    /// - ChaCha20
    ///
    /// # Example
    ///
    /// ```rust
    /// use cryptograph::cryptography::des::encrypt::Des;
    ///
    /// let ciphertext = 0x85E813540F0AB405;
    /// let key = 0x133457799BBCDFF1;
    ///
    /// let plaintext = Des::decrypt(ciphertext, key);
    /// ```
    ///
    /// # References
    ///
    /// - FIPS 46-3
    /// - NIST DES Specification
    /// - Feistel Network Architecture
    pub fn decrypt(y: u64, key: u64) -> u64 {
        let permuted = initial_permutation(y);

        let mut left_x = (permuted >> 32) as u32;
        let mut right_x = permuted as u32;

        let pc = permutated_choice_1(key);

        let mut left_key = (pc >> 28) as u32;
        let mut right_key = (pc & 0x0FFFFFFF) as u32;

        let mut round_keys = [0u64; 16];

        for round in 1..=16 {
            (left_key, right_key) = key_shift(left_key, right_key, round);
            round_keys[(round - 1) as usize] = permutated_choice_2(left_key, right_key);
        }

        for &round_key in round_keys.iter().rev() {
            let temp = right_x;
            right_x = left_x ^ f(right_x, round_key);
            left_x = temp;
        }

        let mut decrypted: u64 = 0;
        decrypted |= left_x as u64;
        decrypted |= (right_x as u64) << 32;

        final_permutation(decrypted)
    }
}
