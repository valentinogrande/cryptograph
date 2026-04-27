//! AES encryption implementation.
//!
//! This module exposes a small, educational API for encrypting a single
//! 128-bit block with AES-128, AES-192, or AES-256.
//!
//! # Example
//!
//! ```rust
//! use cryptograph::cryptography::aes::{Aes, AesEncryptionType};
//!
//! let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
//! let plaintext = 0x00112233445566778899AABBCCDDEEFF;
//!
//! let ciphertext = Aes::new(key, plaintext).encrypt();
//! assert_eq!(ciphertext, 0x69C4E0D86A7B0430D8CDB78070B4C55A);
//! ```

use crate::cryptography::aes::{
    bite_sub::SBOX, key::expand_key, mix_column::mix_columns_state, shift_rows::shift_rows_state,
};
use std::sync::OnceLock;

/// AES-256 key stored as four big-endian 64-bit chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256 {
    pub data: [u64; 4],
}

impl U256 {
    /// Creates a new AES-256 key from four 64-bit chunks in big-endian order.
    pub const fn new(data: [u64; 4]) -> Self {
        Self { data }
    }

    /// Creates a key from the 32-byte representation used in AES test vectors.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut data = [0u64; 4];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            data[index] = u64::from_be_bytes(word);
        }

        Self { data }
    }

    /// Returns the key as 32 bytes in big-endian order.
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, word) in self.data.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }

        bytes
    }
}

/// AES-192 key stored as three big-endian 64-bit chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U192 {
    pub data: [u64; 3],
}

impl U192 {
    /// Creates a new AES-192 key from three 64-bit chunks in big-endian order.
    pub const fn new(data: [u64; 3]) -> Self {
        Self { data }
    }

    /// Creates a key from the 24-byte representation used in AES test vectors.
    pub fn from_be_bytes(bytes: [u8; 24]) -> Self {
        let mut data = [0u64; 3];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            data[index] = u64::from_be_bytes(word);
        }

        Self { data }
    }

    /// Returns the key as 24 bytes in big-endian order.
    pub fn to_be_bytes(self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        for (index, word) in self.data.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }

        bytes
    }
}

/// Supported AES key sizes.
///
/// The numeric values follow the same left-to-right hexadecimal order used in
/// standard AES examples and NIST test vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesEncryptionType {
    /// AES-128 key stored as a single 128-bit value.
    Low(u128),
    /// AES-192 key stored as three 64-bit chunks.
    Medium(U192),
    /// AES-256 key stored as four 64-bit chunks.
    High(U256),
}

impl AesEncryptionType {
    pub(crate) fn key_bytes(self) -> Vec<u8> {
        match self {
            Self::Low(key) => key.to_be_bytes().to_vec(),
            Self::Medium(key) => key.to_be_bytes().to_vec(),
            Self::High(key) => key.to_be_bytes().to_vec(),
        }
    }

    pub(crate) const fn rounds(self) -> usize {
        match self {
            Self::Low(_) => 10,
            Self::Medium(_) => 12,
            Self::High(_) => 14,
        }
    }

    /// Returns the AES key size in bits.
    pub const fn bit_len(self) -> usize {
        match self {
            Self::Low(_) => 128,
            Self::Medium(_) => 192,
            Self::High(_) => 256,
        }
    }
}

/// AES cipher for a single 128-bit block.
///
/// # Examples
///
/// ```rust
/// use cryptograph::cryptography::aes::{Aes, AesEncryptionType};
///
/// let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
/// let plaintext = 0x00112233445566778899AABBCCDDEEFF;
///
/// let aes = Aes::new(key, plaintext);
/// let ciphertext = aes.encrypt();
///
/// assert_eq!(ciphertext, 0x69C4E0D86A7B0430D8CDB78070B4C55A);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aes {
    security: AesEncryptionType,
    x: u128,
}

impl Aes {
    /// Creates a new AES instance for a single 128-bit block.
    pub const fn new(security: AesEncryptionType, x: u128) -> Self {
        Self { security, x }
    }

    /// Encrypts the stored block with the configured key.
    pub fn encrypt(&self) -> u128 {
        encrypt_block(self.x, self.security)
    }
}

pub(crate) fn encrypt_block(block: u128, security: AesEncryptionType) -> u128 {
    let round_keys = expand_key(security);
    let mut state = block.to_be_bytes();

    add_round_key(&mut state, round_keys[0]);

    for round_key in round_keys.iter().take(security.rounds()).skip(1) {
        sub_bytes_state(&mut state);
        shift_rows_state(&mut state);
        mix_columns_state(&mut state);
        add_round_key(&mut state, *round_key);
    }

    sub_bytes_state(&mut state);
    shift_rows_state(&mut state);
    add_round_key(&mut state, round_keys[security.rounds()]);

    u128::from_be_bytes(state)
}

pub(crate) fn add_round_key(state: &mut [u8; 16], round_key: u128) {
    for (byte, key_byte) in state.iter_mut().zip(round_key.to_be_bytes()) {
        *byte ^= key_byte;
    }
}

pub(crate) fn sub_bytes_state(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = substitute_byte(*byte);
    }
}

pub(crate) fn inverse_sub_bytes_state(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = inverse_substitute_byte(*byte);
    }
}

pub(crate) fn substitute_byte(byte: u8) -> u8 {
    SBOX[(byte >> 4) as usize][(byte & 0x0F) as usize]
}

pub(crate) fn inverse_substitute_byte(byte: u8) -> u8 {
    static INVERSE_SBOX: OnceLock<[u8; 256]> = OnceLock::new();

    let table = INVERSE_SBOX.get_or_init(|| {
        let mut inverse = [0u8; 256];
        for candidate in 0..=u8::MAX {
            inverse[substitute_byte(candidate) as usize] = candidate;
        }
        inverse
    });

    table[byte as usize]
}
