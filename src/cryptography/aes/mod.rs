//! # Advanced Encryption Standard (AES)
//!
//! Educational AES building blocks implemented in Rust.
//!
//! This module supports single-block AES-128, AES-192, and AES-256 encryption
//! and decryption, plus the internal transformations usually studied when
//! learning the cipher.
//!
//! # Included Submodules
//!
//! - [`bite_sub`] - S-box generation helpers for the `SubBytes` step.
//! - [`encrypt`] - AES block encryption types and implementation.
//! - [`decrypt`] - AES block decryption via inverse rounds.
//! - [`key`] - AES key expansion.
//! - [`mix_column`] - `MixColumns` and its inverse.
//! - [`shift_rows`] - `ShiftRows` and its inverse.
//!
//! # Round Structure
//!
//! ```text
//! AddRoundKey
//!   -> SubBytes
//!   -> ShiftRows
//!   -> MixColumns
//!   -> AddRoundKey
//! ```
//!
//! The final round omits `MixColumns`, and decryption applies the inverse
//! transformations in reverse order.
//!
//! # Examples
//!
//! AES-128 roundtrip:
//!
//! ```rust
//! use cryptograph::cryptography::aes::{Aes, AesEncryptionType};
//!
//! let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
//! let plaintext = 0x00112233445566778899AABBCCDDEEFF;
//!
//! let ciphertext = Aes::new(key, plaintext).encrypt();
//! let recovered = Aes::decrypt(ciphertext, key);
//!
//! assert_eq!(ciphertext, 0x69C4E0D86A7B0430D8CDB78070B4C55A);
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! AES-256 key construction from raw bytes:
//!
//! ```rust
//! use cryptograph::cryptography::aes::{Aes, AesEncryptionType, U256};
//!
//! let key = U256::from_be_bytes([
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
//!     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
//!     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
//! ]);
//! let plaintext = 0x00112233445566778899AABBCCDDEEFF;
//!
//! let ciphertext = Aes::new(AesEncryptionType::High(key), plaintext).encrypt();
//!
//! assert_eq!(ciphertext, 0x8EA2B7CA516745BFEAFC49904B496089);
//! ```
//!
//! # Security Note
//!
//! This code is intended for learning and experimentation. For production use,
//! prefer audited implementations such as RustCrypto.

pub mod bite_sub;
pub mod decrypt;
pub mod encrypt;
pub mod key;
pub mod mix_column;
pub mod shift_rows;

pub use encrypt::{Aes, AesEncryptionType, U192, U256};

#[cfg(test)]
mod tests {
    use super::{
        Aes, AesEncryptionType, U192, U256,
        key::expand_key,
        mix_column::{inverse_mix_column, mix_column},
        shift_rows::{inverse_shift_rows, shift_rows},
    };

    const PLAINTEXT: u128 = 0x00112233445566778899AABBCCDDEEFF;

    #[test]
    fn aes_128_matches_known_answer_vector() {
        let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
        let expected = 0x69C4E0D86A7B0430D8CDB78070B4C55A;

        assert_eq!(Aes::new(key, PLAINTEXT).encrypt(), expected);
        assert_eq!(Aes::decrypt(expected, key), PLAINTEXT);
    }

    #[test]
    fn aes_192_matches_known_answer_vector() {
        let key = AesEncryptionType::Medium(U192::new([
            0x0001020304050607,
            0x08090A0B0C0D0E0F,
            0x1011121314151617,
        ]));
        let expected = 0xDDA97CA4864CDFE06EAF70A0EC0D7191;

        assert_eq!(Aes::new(key, PLAINTEXT).encrypt(), expected);
        assert_eq!(Aes::decrypt(expected, key), PLAINTEXT);
    }

    #[test]
    fn aes_256_matches_known_answer_vector() {
        let key = AesEncryptionType::High(U256::new([
            0x0001020304050607,
            0x08090A0B0C0D0E0F,
            0x1011121314151617,
            0x18191A1B1C1D1E1F,
        ]));
        let expected = 0x8EA2B7CA516745BFEAFC49904B496089;

        assert_eq!(Aes::new(key, PLAINTEXT).encrypt(), expected);
        assert_eq!(Aes::decrypt(expected, key), PLAINTEXT);
    }

    #[test]
    fn aes_roundtrip_supports_multiple_key_sizes() {
        let cases = [
            (
                AesEncryptionType::Low(0x2B7E151628AED2A6ABF7158809CF4F3C),
                0x6BC1BEE22E409F96E93D7E117393172A,
            ),
            (
                AesEncryptionType::Medium(U192::new([
                    0x8E73B0F7DA0E6452,
                    0xC810F32B809079E5,
                    0x62F8EAD2522C6B7B,
                ])),
                0x6BC1BEE22E409F96E93D7E117393172A,
            ),
            (
                AesEncryptionType::High(U256::new([
                    0x603DEB1015CA71BE,
                    0x2B73AEF0857D7781,
                    0x1F352C073B6108D7,
                    0x2D9810A30914DFF4,
                ])),
                0x6BC1BEE22E409F96E93D7E117393172A,
            ),
        ];

        for (key, plaintext) in cases {
            let ciphertext = Aes::new(key, plaintext).encrypt();
            assert_eq!(Aes::decrypt(ciphertext, key), plaintext);
        }
    }

    #[test]
    fn helper_steps_are_invertible() {
        let state = 0x6353E08C0960E104CD70B751BACAD0E7;

        assert_eq!(inverse_shift_rows(shift_rows(state)), state);
        assert_eq!(inverse_mix_column(mix_column(state)), state);
    }

    #[test]
    fn wrong_key_does_not_recover_plaintext() {
        let key = AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F);
        let wrong_key = AesEncryptionType::Low(0x0F0E0D0C0B0A09080706050403020100);
        let ciphertext = Aes::new(key, PLAINTEXT).encrypt();

        assert_ne!(Aes::decrypt(ciphertext, wrong_key), PLAINTEXT);
    }

    #[test]
    fn key_expansion_returns_round_zero_plus_each_round_key() {
        assert_eq!(
            expand_key(AesEncryptionType::Low(0x000102030405060708090A0B0C0D0E0F)).len(),
            11
        );
        assert_eq!(
            expand_key(AesEncryptionType::Medium(U192::new([
                0x0001020304050607,
                0x08090A0B0C0D0E0F,
                0x1011121314151617,
            ])))
            .len(),
            13
        );
        assert_eq!(
            expand_key(AesEncryptionType::High(U256::new([
                0x0001020304050607,
                0x08090A0B0C0D0E0F,
                0x1011121314151617,
                0x18191A1B1C1D1E1F,
            ])))
            .len(),
            15
        );
    }
}
