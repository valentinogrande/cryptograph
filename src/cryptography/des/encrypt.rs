//! DES encryption implementation
//!
//! A lightweight implementation of the Data Encryption Standard (DES)
//! written in Rust.
//!
//! # Features
//!
//! - Pure Rust
//! - No dependencies
//! - Educational implementation
//!
//! # Example
//!
//! ```rust
//! use cryptograph::cryptography::des::encrypt::Des;
//!
//! let des = Des::new(0x0123456789ABCDEF);
//! let encrypted = des.encrypt(0x133457799BBCDFF1);
//! ```

use crate::cryptography::des::{
    f::f,
    key::{key_shift, permutated_choice_1, permutated_choice_2},
    permutation::{final_permutation, initial_permutation},
};

const ROUNDS: u8 = 16;

/// A Data Encryption Standard (DES) cipher implementation.
///
/// This struct provides encryption for a single 64-bit block using
/// the DES Feistel network.
///
/// # Overview
///
/// The encryption process consists of:
///
/// - Initial permutation (IP)
/// - Key permutation (PC-1)
/// - 16 Feistel rounds
/// - Final swap
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::encrypt::Des;
///
/// let plaintext: u64 = 0x0123456789ABCDEF;
/// let key: u64 = 0x133457799BBCDFF1;
///
/// let des = Des::new(plaintext);
/// let encrypted = des.encrypt(key);
///
/// println!("{:016X}", encrypted);
/// ```
///
/// # Notes
///
/// - This implementation operates on a single 64-bit block
/// - Padding and block chaining modes are not included
/// - Intended for educational and low-level cryptography usage
pub struct Des {
    /// 64-bit input block
    x: u64,
}

impl Des {
    /// Creates a new DES instance with a 64-bit block.
    ///
    /// # Arguments
    ///
    /// * `x` - 64-bit plaintext block
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cryptograph::cryptography::des::encrypt::Des;
    ///
    /// let des = Des::new(0x0123456789ABCDEF);
    /// ```
    pub fn new(x: u64) -> Self {
        Self { x }
    }

    /// Encrypts the stored block using a 64-bit DES key.
    ///
    /// # Arguments
    ///
    /// * `key` - 64-bit DES key
    ///
    /// # Returns
    ///
    /// Encrypted 64-bit block
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cryptograph::cryptography::des::encrypt::Des;
    ///
    /// let plaintext = 0x0123456789ABCDEF;
    /// let key = 0x133457799BBCDFF1;
    ///
    /// let des = Des::new(plaintext);
    /// let encrypted = des.encrypt(key);
    ///
    /// assert_ne!(plaintext, encrypted);
    /// ```
    ///
    /// # Notes
    ///
    /// - Performs 16 DES rounds
    /// - Applies initial permutation
    /// - Applies final swap
    pub fn encrypt(&self, key: u64) -> u64 {
        let permuted = initial_permutation(self.x);
        let pc = permutated_choice_1(key);

        let mut left_key = (pc >> 28) as u32;
        let mut right_key = (pc & 0x0FFFFFFF) as u32;

        let mut left_x = (permuted >> 32) as u32;
        let mut right_x = permuted as u32;

        let (left, right) = round(
            &mut 0,
            &mut left_key,
            &mut right_key,
            &mut left_x,
            &mut right_x,
        );

        let mut encrypted: u64 = 0;
        encrypted |= left as u64;
        encrypted |= (right as u64) << 32;

        final_permutation(encrypted)
    }
}

/// Performs recursive DES Feistel rounds.
///
/// This function applies:
///
/// - Key shifting
/// - Subkey generation
/// - F-function
/// - Feistel swap
///
/// # Arguments
///
/// * `n` - Round counter
/// * `left_key` - Left half of key
/// * `right_key` - Right half of key
/// * `left_x` - Left half of block
/// * `right_x` - Right half of block
///
/// # Returns
///
/// `(left, right)` halves after all rounds
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::des::encrypt::round;
///
/// let mut n = 0;
/// let mut lk = 0;
/// let mut rk = 0;
/// let mut lx = 0;
/// let mut rx = 0;
///
/// let (_l, _r) = round(&mut n, &mut lk, &mut rk, &mut lx, &mut rx);
/// ```
pub fn round(
    n: &mut u8,
    left_key: &mut u32,
    right_key: &mut u32,
    left_x: &mut u32,
    right_x: &mut u32,
) -> (u32, u32) {
    if *n == ROUNDS {
        return (*left_x, *right_x);
    }

    *n += 1;

    (*left_key, *right_key) = key_shift(*left_key, *right_key, *n);

    let key = permutated_choice_2(*left_key, *right_key);
    let temp = *right_x;

    *right_x = *left_x ^ f(*right_x, key);
    *left_x = temp;

    round(n, left_key, right_key, left_x, right_x)
}
